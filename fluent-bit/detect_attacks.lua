function detect_attacks(tag, timestamp, record)
    local log = record["log"] or ""
    
    -- SQL Injection Detection
    if string.match(log, "OR 1=1") or 
       string.match(log, "union select") or 
       string.match(log, "drop table") then
        record["attack_type"] = "sql_injection"
        record["severity"] = "high"
        record["wazuh_alert"] = "true"
    end
    
    -- XSS Detection
    if string.match(log, "<script") or 
       string.match(log, "javascript:") or 
       string.match(log, "alert%(") then
        record["attack_type"] = "xss"
        record["severity"] = "medium"
        record["wazuh_alert"] = "true"
    end
    
    -- Auth Failure Detection
    if string.match(log, "Invalid Credentials") or 
       string.match(log, "authentication failed") then
        record["attack_type"] = "auth_failure"
        record["severity"] = "low"
        record["wazuh_alert"] = "true"
    end
    
    return 1, timestamp, record
end
