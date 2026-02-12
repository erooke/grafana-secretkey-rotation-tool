# Grafana Secret Key Rotation Tool

Tool for rotating Grafana's `secret_key` and re-encrypting all sensitive data in the database.

## Features

- ✅ Re-encrypts all data_keys (envelope DEKs)
- ✅ Re-encrypts alert_notification (legacy secure_settings)
- ✅ Re-encrypts alert_configuration (alertmanager secureSettings, legacy only)
- ✅ Re-encrypts alert_configuration_history
- ✅ Validates encryption with given key
- ✅ Creates automatic database backup
- ✅ Updates grafana.ini with new secret_key

## Usage

## Building

```bash
go mod tidy
go build -o rotate rotate.go
```

## Procedure

1. **Stop Grafana**
2. Run rotation: `./rotate update -db /path/to/grafana.db -ini /path/to/grafana.ini`
3. **Start Grafana**
4. Verify: `./rotate validate -db /path/to/grafana.db -key <new_secret_key>`

### Update (Rotate secret_key)

```bash
./rotate update -db <path>/grafana.db -ini <path>/grafana.ini
```

### Validate

```bash
./rotate validate -db <path>/grafana.db -key <secret_key>
```


