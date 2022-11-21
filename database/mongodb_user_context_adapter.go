package database

import (
	"fmt"

	"github.com/cjlapao/common-go-database/mongodb"
	identity_constants "github.com/cjlapao/common-go-identity/constants"
	"github.com/cjlapao/common-go-identity/models"
)

type MongoDBUserContextAdapter struct {
	currentDatabase string
}

func (u MongoDBUserContextAdapter) GetUserById(id string) *models.User {
	var result models.User
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("_id eq '%v'", id))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) GetUserByEmail(email string) *models.User {
	var result models.User
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("email eq '%v'", email))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) GetUserByUsername(username string) *models.User {
	var result models.User
	repo := u.getMongoDBTenantRepository()
	dbUsers := repo.FindOne(fmt.Sprintf("username eq '%v'", username))
	dbUsers.Decode(&result)
	return &result
}

func (u MongoDBUserContextAdapter) UpsertUser(user models.User) error {
	if user.IsValid() {
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
	} else {
		return ErrUserNotValid
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
		return &user.RefreshToken
	}

	return nil
}

func (u MongoDBUserContextAdapter) UpdateUserRefreshToken(id string, token string) bool {
	user := u.GetUserById(id)
	if user != nil {
		user.RefreshToken = token
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

func (u MongoDBUserContextAdapter) GetUserEmailVerifyToken(id string) *string {
	user := u.GetUserById(id)
	if user != nil {
		return &user.EmailVerifyToken
	}

	return nil
}

func (u MongoDBUserContextAdapter) UpdateUserEmailVerifyToken(id string, token string) bool {
	user := u.GetUserById(id)
	if user != nil {
		user.EmailVerifyToken = token
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
