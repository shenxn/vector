use crate::{
    ast::{Function, FunctionArgument},
    parse_grok::Error as GrokRuntimeError,
    parse_grok_rules::Error as GrokStaticError,
};

use crate::filters::array;
use crate::matchers::date::{apply_date_filter, DateFilter};
use ordered_float::NotNan;
use std::{convert::TryFrom, string::ToString};
use strum_macros::Display;
use vrl_compiler::Value;

#[derive(Debug, Display, Clone)]
pub enum GrokFilter {
    Date(DateFilter),
    Integer,
    IntegerExt,
    // with scientific notation support, e.g. 1e10
    Number,
    NumberExt,
    // with scientific notation support, e.g. 1.52e10
    NullIf(String),
    Scale(f64),
    Lowercase,
    Uppercase,
    Json,
    Array(
        Option<(char, char)>,
        Option<String>,
        Box<Option<GrokFilter>>,
    ),
}

impl TryFrom<&Function> for GrokFilter {
    type Error = GrokStaticError;

    fn try_from(f: &Function) -> Result<Self, Self::Error> {
        match f.name.as_str() {
            "scale" => match f.args.as_ref() {
                Some(args) if !args.is_empty() => {
                    let scale_factor = match args[0] {
                        FunctionArgument::Arg(Value::Integer(scale_factor)) => scale_factor as f64,
                        FunctionArgument::Arg(Value::Float(scale_factor)) => {
                            scale_factor.into_inner()
                        }
                        _ => return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone())),
                    };
                    Ok(GrokFilter::Scale(scale_factor))
                }
                _ => Err(GrokStaticError::InvalidFunctionArguments(f.name.clone())),
            },
            "integer" => Ok(GrokFilter::Integer),
            "integerExt" => Ok(GrokFilter::IntegerExt),
            "number" => Ok(GrokFilter::Number),
            "numberExt" => Ok(GrokFilter::NumberExt),
            "lowercase" => Ok(GrokFilter::Lowercase),
            "uppercase" => Ok(GrokFilter::Uppercase),
            "json" => Ok(GrokFilter::Json),
            "nullIf" => f
                .args
                .as_ref()
                .and_then(|args| {
                    if let FunctionArgument::Arg(Value::Bytes(null_value)) = &args[0] {
                        Some(GrokFilter::NullIf(
                            String::from_utf8_lossy(null_value).to_string(),
                        ))
                    } else {
                        None
                    }
                })
                .ok_or_else(|| GrokStaticError::InvalidFunctionArguments(f.name.clone())),
            "array" => {
                let args_len = f.args.as_ref().map_or(0, |args| args.len());

                let mut delimiter = None;
                let mut value_filter = None;
                let mut brackets = None;
                if args_len == 1 {
                    match &f.args.as_ref().unwrap()[0] {
                        FunctionArgument::Arg(Value::Bytes(ref bytes)) => {
                            delimiter = Some(String::from_utf8_lossy(bytes).to_string());
                        }
                        FunctionArgument::Function(f) => {
                            value_filter = Some(GrokFilter::try_from(f)?)
                        }
                        _ => return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone())),
                    }
                } else if args_len == 2 {
                    match (&f.args.as_ref().unwrap()[0], &f.args.as_ref().unwrap()[1]) {
                        (
                            FunctionArgument::Arg(Value::Bytes(ref brackets_b)),
                            FunctionArgument::Arg(Value::Bytes(ref delimiter_b)),
                        ) => {
                            brackets = Some(String::from_utf8_lossy(brackets_b).to_string());
                            delimiter = Some(String::from_utf8_lossy(delimiter_b).to_string());
                        }
                        (
                            FunctionArgument::Arg(Value::Bytes(ref delimiter_b)),
                            FunctionArgument::Function(f),
                        ) => {
                            delimiter = Some(String::from_utf8_lossy(delimiter_b).to_string());
                            value_filter = Some(GrokFilter::try_from(f)?);
                        }
                        _ => return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone())),
                    }
                } else if args_len == 3 {
                    match (
                        &f.args.as_ref().unwrap()[0],
                        &f.args.as_ref().unwrap()[1],
                        &f.args.as_ref().unwrap()[2],
                    ) {
                        (
                            FunctionArgument::Arg(Value::Bytes(ref brackets_b)),
                            FunctionArgument::Arg(Value::Bytes(ref delimiter_b)),
                            FunctionArgument::Function(f),
                        ) => {
                            brackets = Some(String::from_utf8_lossy(brackets_b).to_string());
                            delimiter = Some(String::from_utf8_lossy(delimiter_b).to_string());
                            value_filter = Some(GrokFilter::try_from(f)?);
                        }
                        _ => return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone())),
                    }
                } else if args_len > 3 {
                    return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone()));
                }

                let brackets = match brackets {
                    Some(b) if b.len() == 1 => {
                        let char = b.chars().next().unwrap();
                        Some((char, char))
                    }
                    Some(b) if b.len() == 2 => {
                        let mut chars = b.chars();
                        Some((chars.next().unwrap(), chars.next().unwrap()))
                    }
                    None => None,
                    _ => {
                        return Err(GrokStaticError::InvalidFunctionArguments(f.name.clone()));
                    }
                };

                Ok(GrokFilter::Array(
                    brackets,
                    delimiter,
                    Box::new(value_filter),
                ))
            }
            _ => Err(GrokStaticError::UnknownFilter(f.name.clone())),
        }
    }
}

/// Applies a given Grok filter to the value and returns the result or error.
/// For detailed description and examples of specific filters check out https://docs.datadoghq.com/logs/log_configuration/parsing/?tab=filters
pub fn apply_filter(value: &Value, filter: &GrokFilter) -> Result<Value, GrokRuntimeError> {
    match filter {
        GrokFilter::Integer => match value {
            Value::Bytes(v) => Ok(String::from_utf8_lossy(v)
                .parse::<i64>()
                .map_err(|_e| {
                    GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
                })?
                .into()),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::IntegerExt => match value {
            Value::Bytes(v) => Ok(String::from_utf8_lossy(v)
                .parse::<f64>()
                .map_err(|_e| {
                    GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
                })
                .map(|f| (f as i64).into())?),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Number | GrokFilter::NumberExt => match value {
            Value::Bytes(v) => Ok(String::from_utf8_lossy(v)
                .parse::<f64>()
                .map_err(|_e| {
                    GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
                })?
                .into()),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Scale(scale_factor) => match value {
            Value::Integer(v) => Ok(Value::Float(
                NotNan::new((*v as f64) * scale_factor).expect("NaN"),
            )),
            Value::Float(v) => Ok(Value::Float(
                NotNan::new(v.into_inner() * scale_factor).expect("NaN"),
            )),
            Value::Bytes(v) => {
                let v = String::from_utf8_lossy(v).parse::<f64>().map_err(|_e| {
                    GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
                })?;
                Ok(Value::Float(
                    NotNan::new(v * scale_factor).expect("NaN").into(),
                ))
            }
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Lowercase => match value {
            Value::Bytes(bytes) => Ok(String::from_utf8_lossy(bytes).to_lowercase().into()),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Uppercase => match value {
            Value::Bytes(bytes) => Ok(String::from_utf8_lossy(bytes).to_uppercase().into()),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Json => match value {
            Value::Bytes(bytes) => serde_json::from_slice::<'_, serde_json::Value>(bytes.as_ref())
                .map_err(|_e| {
                    GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
                })
                .map(|v| v.into()),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::NullIf(null_value) => match value {
            Value::Bytes(bytes) => {
                if String::from_utf8_lossy(bytes) == *null_value {
                    Ok(Value::Null)
                } else {
                    Ok(value.to_owned())
                }
            }
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
        GrokFilter::Date(date_filter) => apply_date_filter(value, date_filter),
        GrokFilter::Array(brackets, delimiter, value_filter) => match value {
            Value::Bytes(bytes) => array::parse(
                String::from_utf8_lossy(&bytes).as_ref(),
                brackets.to_owned(),
                delimiter.as_ref().map(|s| s.as_str()),
            )
            .map_err(|_e| {
                GrokRuntimeError::FailedToApplyFilter(filter.to_string(), value.to_string())
            })
            .and_then(|values| {
                if let Some(value_filter) = value_filter.as_ref() {
                    let result = values
                        .iter()
                        .map(|v| apply_filter(v, value_filter))
                        .collect::<Result<Vec<Value>, _>>()
                        .map(|v| Value::from(v));
                    return result;
                }
                Ok(values.into())
            }),
            _ => Err(GrokRuntimeError::FailedToApplyFilter(
                filter.to_string(),
                value.to_string(),
            )),
        },
    }
}
