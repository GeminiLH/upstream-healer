## Network Requirements

### Docker Networking
The application requires host networking to access the LAN for ARP scanning:
- The healer container must have `network_mode: host` 
- NPM container must be accessible via Docker network
- Required ports: 8787 (web UI), 8181/8182 (NPM web), 3306 (MariaDB)

### LAN Access
The application needs access to:
- Local network for ARP scanning
- NPM container for database access
- Docker socket for container operations

## Data Persistence

### Database Storage
The SQLite database is stored in a named volume called `healer-data`:
- Automatically created on first run
- Persists between deployments
- Data stored in `/data/healer.db`

### Configuration Files
All configuration data (hosts, settings, notifications) is persisted in the SQLite database.

## Backup and Recovery

### Database Backups
```bash
# Create backup of database
docker run --rm \
  -v healer-data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/healer-backup-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
```

### Configuration Backup
All configuration is stored in the database, so backing up the database is sufficient for full recovery.## Troubleshooting

### Common Deployment Issues

#### 1. Docker Permission Errors
```bash
# Fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker
```

#### 2. Port Conflicts
```bash
# Check for port usage
netstat -tuln | grep :8787
lsof -i :8787

# Stop conflicting processes
sudo kill -9 $(lsof -t -i:8787)
```

#### 3. Docker Network Issues
```bash
# Verify network connectivity
docker network ls
docker inspect <container-name>
```

### Health Checks

#### Application Status
```bash
# Check if application is running
docker compose ps

# View application logs
docker compose logs upstream-healer

# Test API endpoint
curl http://localhost:8787/
```

## Monitoring and Maintenance

### Log Management
- Application logs are available via Docker logs
- Diagnostic scan logs are stored in development environment when `UPSTREAM_HEALER_DEBUG_LOG_DIR` is set

### Performance Monitoring
- Monitor CPU and memory usage of containers
- Track database size growth over time
- Monitor network scanning performance

### Regular Maintenance Tasks
1. **Database Cleanup**: Regular review of event retention settings
2. **Log Rotation**: Manage disk space for diagnostic logs
3. **Security Updates**: Keep Docker images updated with security patches
4. **Configuration Review**: Periodic review of monitoring parameters## Upgrade Process

### Standard Upgrade
```bash
# Pull latest code
cd /path/to/upstream-healer
git pull

# Rebuild and redeploy
docker compose up -d --build
```

### Version-Specific Updates
Check `memory-bank/progress.md` for any migration requirements or breaking changes between versions.

## Security Considerations

### Network Security
- The application exposes port 8787 for web access
- Access should be restricted to trusted networks
- Consider using reverse proxy with authentication for external access

### Data Security
- All sensitive data (passwords, tokens) are stored in the database
- Database files are persisted in a Docker volume
- Network traffic between containers is internal and secure

### Container Security
- Run containers with minimal required privileges
- Keep container images updated with security patches
- Use read-only file systems where possible

## Production Deployment Best Practices

1. **Use HTTPS**: Deploy behind a reverse proxy with SSL/TLS termination
2. **Environment Separation**: Maintain separate configurations for dev, staging, and production
3. **Monitoring**: Set up monitoring for application health and performance
4. **Backup Strategy**: Implement regular database backup procedures
5. **Access Control**: Restrict direct access to the application container
6. **Logging**: Configure proper log aggregation for troubleshooting
7. **Scalability**: Plan for increased load if monitoring more hosts

## Troubleshooting Checklist

### Pre-Deployment
- [ ] Verify Docker installation and permissions
- [ ] Check network connectivity to monitored devices  
- [ ] Ensure required ports are available
- [ ] Review configuration settings
- [ ] Test basic connectivity to NPM container

### Post-Deployment
- [ ] Verify application is running (`docker compose ps`)
- [ ] Test API endpoints with curl or browser
- [ ] Check logs for errors (`docker compose logs`)
- [ ] Verify host monitoring functionality
- [ ] Confirm notification channels are working