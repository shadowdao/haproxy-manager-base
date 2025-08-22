# HAProxy Manager Migration Guide: ACL to Map Files

## Critical Issue Fixed

HAProxy has a **64 word limit per ACL line**, which caused the following error when too many IPs were blocked:

```
[ALERT] (1485) : config : parsing [/etc/haproxy/haproxy.cfg:58]: too many words, truncating after word 64, position 880: <197.5.145.73>.
[ALERT] (1485) : config : parsing [/etc/haproxy/haproxy.cfg:61] : error detected while parsing an 'http-request set-path' condition : no such ACL : 'is_blocked'.
```

This caused HAProxy to drop traffic for **ALL sites**, creating a critical outage.

## Solution: Map Files

We've migrated from ACL-based IP blocking to **HAProxy map files** which:

✅ **No word limits** - handle millions of IPs  
✅ **Runtime updates** - no config reloads needed  
✅ **Better performance** - hash table lookups instead of linear search  
✅ **Config validation** - automatic rollback on failures  
✅ **Backup/restore** - automatic backup before any changes  

## What Changed

### Before (Problematic ACL Method)
```haproxy
# In haproxy.cfg template
acl is_blocked src 192.168.1.1 192.168.1.2 ... (64 word limit!)
http-request set-path /blocked-ip if is_blocked
```

### After (Map File Method)
```haproxy
# In haproxy.cfg
http-request deny status 403 if { src -f /etc/haproxy/blocked_ips.map }

# In /etc/haproxy/blocked_ips.map
192.168.1.1
192.168.1.2
64.235.37.112
```

## New Features

### 1. Safe Configuration Management
- **Automatic backups** before any changes
- **Configuration validation** before applying
- **Automatic rollback** if validation fails
- **Graceful error handling**

### 2. Runtime IP Management
```bash
# Add IP without reload (immediate effect)
echo "add map #0 192.168.1.100" | socat stdio /var/run/haproxy.sock

# Remove IP without reload
echo "del map #0 192.168.1.100" | socat stdio /var/run/haproxy.sock
```

### 3. New API Endpoints

#### Safe Config Reload
```bash
curl -X POST http://localhost:8000/api/config/reload \
  -H "Authorization: Bearer your-api-key"
```

#### Sync Runtime Maps
```bash
curl -X POST http://localhost:8000/api/blocked-ips/sync \
  -H "Authorization: Bearer your-api-key"
```

## Migration Process

### Automatic Migration
The system automatically:
1. Creates `/etc/haproxy/blocked_ips.map` from database
2. Updates HAProxy config to use map files
3. Validates new configuration
4. Creates backups before applying changes

### Manual Migration (if needed)
```bash
# 1. Stop HAProxy manager
systemctl stop haproxy-manager

# 2. Backup current config
cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.backup

# 3. Update HAProxy manager code
git pull origin main

# 4. Start HAProxy manager
systemctl start haproxy-manager

# 5. Trigger config regeneration
curl -X POST http://localhost:8000/api/config/reload \
  -H "Authorization: Bearer your-api-key"
```

## Rollback Plan

If issues occur, the system automatically:

1. **Restores backup configuration**
2. **Reloads HAProxy with known-good config**
3. **Logs all errors for debugging**

Manual rollback if needed:
```bash
# Restore backup
cp /etc/haproxy/haproxy.cfg.backup /etc/haproxy/haproxy.cfg
systemctl reload haproxy
```

## Performance Benefits

| Feature | Old ACL Method | New Map Method |
|---------|---------------|----------------|
| **IP Limit** | 64 IPs max | Unlimited |
| **Updates** | Full reload required | Runtime updates |
| **Lookup Speed** | O(n) linear | O(1) hash table |
| **Memory Usage** | High (all in config) | Low (external file) |
| **Restart Required** | Yes | No |

## Monitoring

Check HAProxy manager logs for any issues:
```bash
tail -f /var/log/haproxy-manager.log
```

Key log entries to watch for:
- `Configuration validation passed/failed`
- `Backup created/restored`
- `Runtime map updated`
- `Safe reload completed`

## Troubleshooting

### Map File Not Found
```bash
# Check if map file exists
ls -la /etc/haproxy/blocked_ips.map

# Manually create if missing
curl -X POST http://localhost:8000/api/blocked-ips/sync \
  -H "Authorization: Bearer your-api-key"
```

### Runtime Updates Not Working
```bash
# Check HAProxy stats socket
ls -la /var/run/haproxy.sock /tmp/haproxy-cli

# Test socket connection
echo "show info" | socat stdio /var/run/haproxy.sock
```

### Config Validation Failures
The system automatically:
1. Creates backup before changes
2. Validates new config
3. Restores backup if validation fails
4. Logs detailed error messages

## Future Enhancements

- **Geographic IP blocking** using map files
- **Rate limiting integration** 
- **Automatic threat feed integration**
- **API rate limiting per client**

## HAProxy Version Compatibility

Map files require **HAProxy 1.6+** (released December 2015)
- ✅ HAProxy 1.6+ (Map files supported)
- ❌ HAProxy 1.5 and older (Not supported)

Check your version:
```bash
haproxy -v
```