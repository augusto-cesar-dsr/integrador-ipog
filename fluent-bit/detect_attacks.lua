function detect_attacks(tag, timestamp, record)
    local log = record["log"]
    if not log then
        return 0, 0, 0
    end
    
    -- SQL Injection
    if string.match(log, "OR 1=1") or string.match(log, "union select") then
        record["attack_type"] = "sql_injection"
        record["severity"] = "high"
    end
    
    -- XSS
    if string.match(log, "<script>") or string.match(log, "javascript:") then
        record["attack_type"] = "xss"
        record["severity"] = "medium"
    end
    
    -- Path Traversal
    if string.match(log, "/etc/passwd") or string.match(log, "/etc/shadow") then
        record["attack_type"] = "path_traversal"
        record["severity"] = "high"
    end
    
    return 1, timestamp, record
end
