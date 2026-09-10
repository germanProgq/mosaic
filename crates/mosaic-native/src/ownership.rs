use serde_json::Value;

pub fn rule(value: &Value, priority: &str, table: &str) -> bool {
    value["priority"].as_u64() == priority.parse().ok()
        && (value["table"].as_u64() == table.parse().ok() || value["table"].as_str() == Some(table))
        && value["fwmark"].as_str() == Some("0x4d4f")
        && value["src"].as_str() == Some("all")
        && value.get("fwmask").is_none_or(|mask| mask == "0xffffffff")
        && value
            .get("not")
            .is_some_and(|flag| flag.is_null() || flag.as_bool() == Some(true))
        && value.as_object().is_some_and(|fields| {
            fields.keys().all(|name| {
                matches!(
                    name.as_str(),
                    "priority" | "table" | "fwmark" | "fwmask" | "src" | "not" | "protocol"
                )
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverted_rule_accepts_iproute_null_and_rejects_other_selectors() {
        let mut value = serde_json::json!({"priority":10990,"not":null,"src":"all","fwmark":"0x4d4f","table":19791});
        assert!(rule(&value, "10990", "19791"));
        value["not"] = false.into();
        assert!(!rule(&value, "10990", "19791"));
        value["not"] = Value::Null;
        value["dst"] = "203.0.113.0/24".into();
        assert!(!rule(&value, "10990", "19791"));
        value.as_object_mut().unwrap().remove("dst");
        value["fwmask"] = "0xffff".into();
        assert!(!rule(&value, "10990", "19791"));
    }
}
