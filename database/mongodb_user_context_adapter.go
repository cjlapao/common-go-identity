package database

import (
	"fmt"

	"github.com/cjlapao/common-go-database/mongodb"
	"github.com/cjlapao/common-go-identity/constants"
	identity_constants "github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/database/dto"
	"github.com/cjlapao/common-go/security"
)

type MongoDBUserContextAdapter struct {
	currentDatabase string
}

func (u MongoDBUserContextAdapter) GetUserById(id string) *dto.UserDTO {
	var result dto.UserDTO
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("_id eq '%v'", id))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) GetUserByEmail(email string) *dto.UserDTO {
	var result dto.UserDTO
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("email eq '%v'", email))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) GetUserByUsername(username string) *dto.UserDTO {
	var result dto.UserDTO
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("username eq '%v'", username))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) UpsertUser(user dto.UserDTO) error {
	user.Password = security.SHA256Encode(user.Password)
	repo := u.getMongoDBTenantRepository()
	logger.Info("Upserting user %v into database %v", u.currentDatabase)
	builder, err := mongodb.NewUpdateOneModelBuilder().FilterBy("_id", mongodb.Equal, user.ID).Encode(user).Build()
	if err != nil {
		return err
	}
	result, err := repo.UpsertOne(builder)
	if err != nil {
		logger.Error("There was an error upserting user %v, %v", user.Email, err.Error())
		return err
	}
	if result.MatchedCount <= 0 {
		logger.Error("There was an error upserting user %v", user.Email)
		return ErrUnknown
	}

	return nil
}

func (u MongoDBUserContextAdapter) RemoveUser(id string) bool {
	if id == "" {
		return false
	}

	repo := u.getMongoDBTenantRepository()
	logger.Info("Removing user %v from database %v", u.currentDatabase)
	builder, err := mongodb.NewDeleteOneBuilder().FilterBy("_id", mongodb.Equal, id).Build()
	if err != nil {
		return false
	}
	result, err := repo.DeleteOne(builder)
	if err != nil {
		logger.Exception(err, "there was an error removing user from collection with id %v", id)
	}
	if result.DeletedCount <= 0 {
		logger.Error("There was an error removing userid %v", id)
	}

	return true
}

func (u MongoDBUserContextAdapter) GetUserRefreshToken(id string) *string {
	user := u.GetUserById(id)
	if user != nil {
		return user.RefreshToken
	}

	return nil
}

func (u MongoDBUserContextAdapter) UpdateUserRefreshToken(id string, token string) bool {
	user := u.GetUserById(id)
	if user != nil {
		user.RefreshToken = &token
		repo := u.getMongoDBTenantRepository()
		builder, err := mongodb.NewUpdateOneModelBuilder().FilterBy("_id", mongodb.Equal, id).Encode(user).Build()
		if err != nil {
			return false
		}

		result, err := repo.UpsertOne(builder)
		if err != nil {
			logger.Exception(err, "There was an error while upserting the refresh token with id %v", id)
			return false
		}
		if result.MatchedCount == 0 && result.ModifiedCount == 0 && result.UpsertedCount == 0 {
			logger.Error("There was an error updating the refresh token for user with id %v", id)
			return false
		}
		return true
	}

	return false
}

func (u MongoDBUserContextAdapter) GetUserEmailVerificationToken(id string) *string {
	user := u.GetUserById(id)
	if user != nil {
		return user.EmailVerifyToken
	}

	return nil
}

func (u MongoDBUserContextAdapter) UpdateUserEmailVerificationToken(id string, token string) bool {
	user := u.GetUserById(id)
	if user != nil {
		user.EmailVerifyToken = &token
		repo := u.getMongoDBTenantRepository()
		builder, _ := mongodb.NewUpdateOneModelBuilder().FilterBy("_id", mongodb.Equal, id).Encode(user).Build()
		result, err := repo.UpsertOne(builder)
		if err != nil {
			logger.Exception(err, "There was an error upserting the email verification token with id %v", id)
			return false
		}
		if result.MatchedCount <= 0 {
			logger.Error("There was an error updating the verify email token for user with id %v", id)
			return false
		}
		return true
	}

	return false
}

func (u MongoDBUserContextAdapter) getMongoDBTenantRepository() mongodb.MongoRepository {
	mongodbSvc := mongodb.Get()
	userRepo := mongodbSvc.TenantDatabase().NewRepository(identity_constants.IdentityUsersCollection)
	return userRepo
}

// TODO: Implement MongoDB GetUserClaimsById
func (u MongoDBUserContextAdapter) GetUserClaimsById(id string) []dto.UserClaimDTO {
	result := make([]dto.UserClaimDTO, 0)

	return result
}

// TODO: Implement MongoDB UpsertUserClaims
func (u MongoDBUserContextAdapter) UpsertUserClaims(user dto.UserDTO) error {
	return nil
}

// TODO: Implement MongoDB GetUserRolesById
func (u MongoDBUserContextAdapter) GetUserRolesById(id string) []dto.UserRoleDTO {
	result := make([]dto.UserRoleDTO, 0)
	return result
}

// TODO: Implement MongoDB UpsertUserRoles
func (u MongoDBUserContextAdapter) UpsertUserRoles(user dto.UserDTO) error {
	return nil
}

// TODO: Implement MongoDB CleanUserRecoveryToken
func (u MongoDBUserContextAdapter) CleanUserRecoveryToken(id string) error {
	return nil
}

// TODO: Implement MongoDB UpdateUserRecoverToken
func (u MongoDBUserContextAdapter) UpdateUserRecoveryToken(id string, token string) bool {
	return false
}

// TODO: Implement MongoDB GetUserRecoveryToken
func (u MongoDBUserContextAdapter) GetUserRecoveryToken(id string) *string {
	result := ""
	return &result
}

// TODO: Implement MongoDB GetUserRecoveryToken
func (u MongoDBUserContextAdapter) UpdateUserPassword(id string, password string) error {
	return nil
}

// TODO: Implement MongoDB CleanUserEmailVerificationToken
func (u MongoDBUserContextAdapter) CleanUserEmailVerificationToken(id string) error {
	return nil
}

// TODO: Implement MongoDB UpdateVerifyUserEmail
func (u MongoDBUserContextAdapter) SetEmailVerificationState(id string, state bool) bool {
	return false
}

func SeedMongoDb(factory *mongodb.MongoFactory, databaseName string) {
	SeedMongoDbUsers(factory, databaseName)
}

func SeedMongoDbUsers(factory *mongodb.MongoFactory, databaseName string) {
	repo := factory.NewDatabaseRepository(databaseName, constants.IdentityUsersCollection)
	users := GetDefaultUsers()
	for _, user := range users {
		model, err := mongodb.NewUpdateOneModelBuilder().FilterBy("email", mongodb.Equal, user.Email).Encode(user, "refreshToken").Build()
		if err != nil {
			logger.Error("There was an error upserting user %v during seeding", user.Email)
		}
		repo.UpsertOne(model)
	}
}
