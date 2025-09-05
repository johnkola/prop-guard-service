package service

import (
	"context"
	"fmt"
	"log"
	"time"

	"PropGuard/internal/config"
	"PropGuard/internal/entity"
	"PropGuard/internal/repository"

	"golang.org/x/crypto/bcrypt"
)

type BootstrapServiceBadger struct {
	client            *repository.BadgerClient
	config            *config.Config
	encryptionService EncryptionService
}

func NewBootstrapServiceBadger(client *repository.BadgerClient, config *config.Config) *BootstrapServiceBadger {
	encryptionService := NewEncryptionService(config.Vault.MasterKey)
	return &BootstrapServiceBadger{
		client:            client,
		config:            config,
		encryptionService: encryptionService,
	}
}

func (s *BootstrapServiceBadger) IsFirstRun(ctx context.Context) (bool, error) {
	exists, err := s.client.Exists(ctx, "system:bootstrapped")
	if err != nil {
		return false, fmt.Errorf("failed to check bootstrap status: %w", err)
	}

	if exists {
		return false, nil
	}

	adminRoleExists, err := s.client.Exists(ctx, "role:role_admin")
	if err != nil {
		return false, fmt.Errorf("failed to check admin role existence: %w", err)
	}

	return !adminRoleExists, nil
}

func (s *BootstrapServiceBadger) RunBootstrap(ctx context.Context) error {
	log.Println("🌱 Starting PropGuard bootstrap process...")

	isFirstRun, err := s.IsFirstRun(ctx)
	if err != nil {
		return fmt.Errorf("failed to check first run status: %w", err)
	}

	if !isFirstRun {
		log.Println("⚠️  Bootstrap attempted but system already initialized")
		return fmt.Errorf("system already bootstrapped")
	}

	if err := s.setBootstrapFlag(ctx); err != nil {
		return fmt.Errorf("failed to set bootstrap flag: %w", err)
	}

	if err := s.seedSystemRoles(ctx); err != nil {
		return fmt.Errorf("failed to seed system roles: %w", err)
	}

	if err := s.createDefaultAdmin(ctx); err != nil {
		return fmt.Errorf("failed to create default admin: %w", err)
	}

	if err := s.createDefaultTeam(ctx); err != nil {
		return fmt.Errorf("failed to create default team: %w", err)
	}

	if err := s.setDefaultConfig(ctx); err != nil {
		return fmt.Errorf("failed to set default config: %w", err)
	}

	log.Println("✅ Bootstrap complete - PropGuard ready for use")
	log.Printf("📋 Default admin credentials:")
	log.Printf("   Username: %s", s.config.Bootstrap.AdminUsername)
	log.Printf("   Password: %s", s.config.Bootstrap.AdminPassword)
	log.Printf("   Email: %s", s.config.Bootstrap.AdminEmail)
	log.Println("🔐 IMPORTANT: Change default password immediately!")

	return nil
}

func (s *BootstrapServiceBadger) setBootstrapFlag(ctx context.Context) error {
	now := time.Now()

	if err := s.client.Set(ctx, "system:bootstrapped", []byte("true")); err != nil {
		return err
	}
	if err := s.client.Set(ctx, "system:bootstrap_date", []byte(now.Format(time.RFC3339))); err != nil {
		return err
	}
	if err := s.client.Set(ctx, "system:bootstrap_version", []byte("1.0.0")); err != nil {
		return err
	}

	log.Println("✓ Bootstrap flags set")
	return nil
}

func (s *BootstrapServiceBadger) seedSystemRoles(ctx context.Context) error {
	log.Println("Creating system roles...")

	roles := entity.GetSystemRoles()

	return s.client.Transaction(ctx, func(txn *repository.Transaction) error {
		var roleIDs []string

		for _, role := range roles {
			roleKey := fmt.Sprintf("role:%s", role.ID)
			if err := s.client.SetJSON(ctx, roleKey, role); err != nil {
				return fmt.Errorf("failed to store role %s: %w", role.Name, err)
			}

			roleIDs = append(roleIDs, role.ID)
			log.Printf("✓ Created role: %s (%s)", role.Name, role.ID)
		}

		if err := s.client.SetJSON(ctx, "roles:index", roleIDs); err != nil {
			return fmt.Errorf("failed to update roles index: %w", err)
		}

		log.Printf("✅ Created %d system roles", len(roles))
		return nil
	})
}

func (s *BootstrapServiceBadger) createDefaultAdmin(ctx context.Context) error {
	log.Println("Creating default admin user...")

	// Use bcrypt for password hashing (compatible with auth service)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(s.config.Bootstrap.AdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}
	passwordHash := string(hashedPassword)

	admin := entity.NewVaultUser(
		s.config.Bootstrap.AdminUsername,
		s.config.Bootstrap.AdminEmail,
		passwordHash,
	)

	admin.RoleIDs = []string{"role_admin"}

	if admin.Metadata == nil {
		admin.Metadata = make(map[string]interface{})
	}
	admin.Metadata["created_by"] = "bootstrap"
	admin.Metadata["is_bootstrap_admin"] = "true"

	return s.client.Transaction(ctx, func(txn *repository.Transaction) error {
		userKey := fmt.Sprintf("user:%s", admin.ID.String())
		if err := s.client.SetJSON(ctx, userKey, admin); err != nil {
			return fmt.Errorf("failed to store admin user: %w", err)
		}

		if err := s.client.Set(ctx, fmt.Sprintf("username:%s", admin.Username), []byte(admin.ID.String())); err != nil {
			return fmt.Errorf("failed to create username index: %w", err)
		}

		if err := s.client.Set(ctx, fmt.Sprintf("email:%s", admin.Email), []byte(admin.ID.String())); err != nil {
			return fmt.Errorf("failed to create email index: %w", err)
		}

		userIDs := []string{admin.ID.String()}
		if err := s.client.SetJSON(ctx, "users:index", userIDs); err != nil {
			return fmt.Errorf("failed to update users index: %w", err)
		}

		log.Printf("✅ Default admin user created: %s", admin.Username)
		return nil
	})
}

func (s *BootstrapServiceBadger) createDefaultTeam(ctx context.Context) error {
	log.Println("Creating default team workspace...")

	adminIDBytes, err := s.client.Get(ctx, fmt.Sprintf("username:%s", s.config.Bootstrap.AdminUsername))
	if err != nil {
		return fmt.Errorf("failed to get admin user ID: %w", err)
	}
	adminID := string(adminIDBytes)

	team := entity.NewTeam("Default Team", adminID)
	team.Description = "Default team workspace created during bootstrap"

	if err := team.AddMember(adminID, "role_admin", "bootstrap"); err != nil {
		return fmt.Errorf("failed to add admin to default team: %w", err)
	}

	return s.client.Transaction(ctx, func(txn *repository.Transaction) error {
		teamKey := fmt.Sprintf("team:%s", team.ID)
		if err := s.client.SetJSON(ctx, teamKey, team); err != nil {
			return fmt.Errorf("failed to store default team: %w", err)
		}

		teamIDs := []string{team.ID}
		if err := s.client.SetJSON(ctx, "teams:index", teamIDs); err != nil {
			return fmt.Errorf("failed to update teams index: %w", err)
		}

		if err := s.client.Set(ctx, "system:default_team_id", []byte(team.ID)); err != nil {
			return fmt.Errorf("failed to set default team ID: %w", err)
		}

		log.Printf("✅ Default team created: %s", team.Name)
		return nil
	})
}

func (s *BootstrapServiceBadger) setDefaultConfig(ctx context.Context) error {
	log.Println("Setting default system configuration...")

	configs := map[string]string{
		"config:system:name":                              "PropGuard",
		"config:system:version":                           "1.0.0",
		"config:system:initialized_at":                    time.Now().Format(time.RFC3339),
		"config:security:mfa_required":                    "false",
		"config:security:session_timeout_minutes":         "60",
		"config:security:max_login_attempts":              "5",
		"config:security:account_lockout_minutes":         "15",
		"config:features:api_keys_enabled":                "true",
		"config:features:audit_logging_enabled":           "true",
		"config:features:secret_rotation_enabled":         "true",
		"config:features:missing_values_tracking_enabled": "true",
		"config:notifications:admin_alerts_enabled":       "true",
		"config:notifications:missing_values_threshold":   "5",
	}

	return s.client.Transaction(ctx, func(txn *repository.Transaction) error {
		for key, value := range configs {
			if err := s.client.Set(ctx, key, []byte(value)); err != nil {
				return fmt.Errorf("failed to set config %s: %w", key, err)
			}
		}

		log.Println("✅ Default system configuration loaded")
		return nil
	})
}

func (s *BootstrapServiceBadger) GetBootstrapStatus(ctx context.Context) (map[string]interface{}, error) {
	status := make(map[string]interface{})

	bootstrapped, err := s.client.Exists(ctx, "system:bootstrapped")
	if err != nil {
		return nil, fmt.Errorf("failed to check bootstrap status: %w", err)
	}
	status["bootstrapped"] = bootstrapped

	if bootstrapped {
		if dateBytes, err := s.client.Get(ctx, "system:bootstrap_date"); err == nil {
			status["bootstrap_date"] = string(dateBytes)
		}

		if versionBytes, err := s.client.Get(ctx, "system:bootstrap_version"); err == nil {
			status["bootstrap_version"] = string(versionBytes)
		}

		var roleIDs []string
		if err := s.client.GetJSON(ctx, "roles:index", &roleIDs); err == nil {
			status["system_roles_count"] = len(roleIDs)
		} else {
			status["system_roles_count"] = 0
		}

		var userIDs []string
		if err := s.client.GetJSON(ctx, "users:index", &userIDs); err == nil {
			status["users_count"] = len(userIDs)
		} else {
			status["users_count"] = 0
		}

		var teamIDs []string
		if err := s.client.GetJSON(ctx, "teams:index", &teamIDs); err == nil {
			status["teams_count"] = len(teamIDs)
		} else {
			status["teams_count"] = 0
		}
	}

	return status, nil
}
