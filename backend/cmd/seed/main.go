package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/golang-cz/devslog"
	"golang.org/x/crypto/bcrypt"

	"github.com/naxumi/soc-ticketing/internal/config"
	"github.com/naxumi/soc-ticketing/internal/domain/user"
	"github.com/naxumi/soc-ticketing/internal/pkg/database"
	"github.com/naxumi/soc-ticketing/internal/repository/postgresql"
)

type seedUser struct {
	FullName string
	Username string
	Password string
	Role     user.Role
}

func main() {
	seedUsers := defaultSeedUsers()

	var err error
	seedUsers, err = promptSeedUsers(seedUsers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed reading terminal input: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	isDev := strings.EqualFold(cfg.App.Env, "development")
	logger := newLogger(isDev)
	logger.Info("seed starting", "env", cfg.App.Env, "target_users", len(seedUsers))

	for _, su := range seedUsers {
		if err := validateSeedInputs(su.FullName, su.Username, su.Password); err != nil {
			logger.Error("invalid seed input", "username", su.Username, "role", su.Role, "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := database.New(ctx, cfg.Database)
	if err != nil {
		logger.Error("failed to connect db", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	userRepo := postgresql.NewUserRepository(db)

	createdCount := 0
	existingCount := 0

	for _, su := range seedUsers {
		// Idempotent by username.
		existing, err := userRepo.GetByUsername(ctx, su.Username)
		if err == nil {
			existingCount++
			logger.Info("user already exists", "id", existing.ID, "username", existing.Username, "role", existing.Role)
			continue
		}
		if !errors.Is(err, user.ErrUserNotFound) {
			logger.Error("failed checking existing user", "username", su.Username, "role", su.Role, "error", err)
			os.Exit(1)
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(su.Password), bcrypt.DefaultCost)
		if err != nil {
			logger.Error("failed hashing password", "username", su.Username, "role", su.Role, "error", err)
			os.Exit(1)
		}

		created, err := userRepo.Create(ctx, user.User{
			FullName:     su.FullName,
			Username:     su.Username,
			PasswordHash: string(hash),
			Role:         su.Role,
		})
		if err != nil {
			if errors.Is(err, user.ErrUsernameExists) {
				existingCount++
				logger.Info("user already exists", "username", su.Username, "role", su.Role)
				continue
			}
			logger.Error("failed creating user", "username", su.Username, "role", su.Role, "error", err)
			os.Exit(1)
		}

		createdCount++
		logger.Info("user created", "id", created.ID, "username", created.Username, "role", created.Role)
	}

	logger.Info("seed completed", "target_users", len(seedUsers), "created", createdCount, "existing", existingCount)
}

func newLogger(isDev bool) *slog.Logger {
	opts := &slog.HandlerOptions{AddSource: !isDev}
	if isDev {
		return slog.New(devslog.NewHandler(os.Stdout, &devslog.Options{
			SortKeys:       true,
			HandlerOptions: opts,
		}))
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func defaultSeedUsers() []seedUser {
	socManagerPassword := "SocManager@123"
	analystPassword := "Analyst@123"

	return []seedUser{
		{
			FullName: "Rizky Pratama",
			Username: "rizky.pratama",
			Password: socManagerPassword,
			Role:     user.RoleSOCManager,
		},
		{
			FullName: "Nadia Putri",
			Username: "nadia.putri",
			Password: analystPassword,
			Role:     user.RoleL1Analyst,
		},
		{
			FullName: "Fajar Maulana",
			Username: "fajar.maulana",
			Password: analystPassword,
			Role:     user.RoleL1Analyst,
		},
		{
			FullName: "Dimas Saputra",
			Username: "dimas.saputra",
			Password: analystPassword,
			Role:     user.RoleL2Analyst,
		},
		{
			FullName: "Aulia Rahman",
			Username: "aulia.rahman",
			Password: analystPassword,
			Role:     user.RoleL2Analyst,
		},
	}
}

func promptSeedUsers(users []seedUser) ([]seedUser, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== SOC User Seeding ===")
	fmt.Println("Tekan Enter untuk pakai default value.")
	fmt.Println()

	roleCounter := map[user.Role]int{}
	for i := range users {
		roleCounter[users[i].Role]++
		label := rolePromptLabel(users[i].Role, roleCounter[users[i].Role])

		fullName, err := promptWithDefault(reader, fmt.Sprintf("%s full name", label), users[i].FullName)
		if err != nil {
			return nil, err
		}
		username, err := promptWithDefault(reader, fmt.Sprintf("%s username", label), users[i].Username)
		if err != nil {
			return nil, err
		}

		users[i].FullName = fullName
		users[i].Username = username
	}

	fmt.Println()
	socPassword, err := promptWithDefault(reader, "SOC_MANAGER password", users[0].Password)
	if err != nil {
		return nil, err
	}
	analystPassword, err := promptWithDefault(reader, "L1/L2 analyst password", users[1].Password)
	if err != nil {
		return nil, err
	}

	for i := range users {
		if users[i].Role == user.RoleSOCManager {
			users[i].Password = socPassword
			continue
		}
		users[i].Password = analystPassword
	}

	return users, nil
}

func rolePromptLabel(role user.Role, idx int) string {
	switch role {
	case user.RoleSOCManager:
		return "SOC_MANAGER"
	case user.RoleL1Analyst:
		return fmt.Sprintf("L1_ANALYST_%d", idx)
	case user.RoleL2Analyst:
		return fmt.Sprintf("L2_ANALYST_%d", idx)
	default:
		return fmt.Sprintf("USER_%d", idx)
	}
}

func promptWithDefault(reader *bufio.Reader, label, defaultValue string) (string, error) {
	fmt.Printf("%s [%s]: ", label, defaultValue)

	text, err := reader.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			text = strings.TrimSpace(text)
			if text == "" {
				return strings.TrimSpace(defaultValue), nil
			}
			return text, nil
		}
		return "", err
	}

	text = strings.TrimSpace(text)
	if text == "" {
		return strings.TrimSpace(defaultValue), nil
	}
	return text, nil
}

func validateSeedInputs(fullName, username, password string) error {
	fullName = strings.TrimSpace(fullName)
	username = strings.TrimSpace(username)

	if fullName == "" {
		return fmt.Errorf("full-name is required")
	}
	if len(fullName) > 100 {
		return fmt.Errorf("full-name must not exceed 100 characters")
	}

	if username == "" {
		return fmt.Errorf("username is required")
	}
	if len(username) > 50 {
		return fmt.Errorf("username must not exceed 50 characters")
	}
	if strings.ContainsAny(username, " \t\n\r") {
		return fmt.Errorf("username must not contain spaces")
	}

	if password == "" {
		return fmt.Errorf("password is required")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len(password) > 255 {
		return fmt.Errorf("password must not exceed 255 characters")
	}

	return nil
}
