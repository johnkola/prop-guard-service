// MongoDB initialization script for JVault
db = db.getSiblingDB('jvault');

// Create jvault user
db.createUser({
  user: 'jvault',
  pwd: 'jvault',
  roles: [
    {
      role: 'readWrite',
      db: 'jvault'
    }
  ]
});

// Create collections (optional, as they'll be created automatically)
db.createCollection('vault_users');
db.createCollection('secrets');
db.createCollection('audit_logs');
db.createCollection('secret_policies');
db.createCollection('secret_rotation_history');

print('JVault database initialized successfully');