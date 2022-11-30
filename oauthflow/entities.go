package oauthflow

import "github.com/cjlapao/common-go-identity/models"

type OAuthRegistrationResponse struct {
	ID            string             `json:"id"`
	Email         string             `json:"email"`
	EmailVerified bool               `json:"emailVerified"`
	FirstName     string             `json:"firstName" bson:"firstName"`
	LastName      string             `json:"lastName" bson:"lastName"`
	DisplayName   string             `json:"displayName" bson:"displayName"`
	Roles         []models.UserRole  `json:"roles" bson:"roles"`
	Claims        []models.UserClaim `json:"claims" bson:"claims"`
}
