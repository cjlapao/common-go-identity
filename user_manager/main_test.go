package user_manager

import (
	"reflect"
	"testing"

	"github.com/cjlapao/common-go-identity/authorization_context"
)

func TestUserManager_ValidatePasswordAllOff(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: false,
		RequiresSpecial: false,
		MinimumSize:     8,
		RequiresNumber:  false,
		AllowsSpaces:    true,
	}

	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want bool
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: false,
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: true,
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); got.IsValid() != tt.want {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserManager_ValidatePasswordRequireCapital(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: true,
		RequiresSpecial: false,
		MinimumSize:     8,
		RequiresNumber:  false,
		AllowsSpaces:    true,
	}

	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want bool
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: false,
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: false,
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); got.IsValid() != tt.want {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserManager_ValidatePasswordRequireSpecial(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: false,
		RequiresSpecial: true,
		MinimumSize:     8,
		RequiresNumber:  false,
		AllowsSpaces:    true,
		AllowedSpecials: "@$!%*#?&",
	}

	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want bool
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: false,
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: false,
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: false,
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: false,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers and special",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); got.IsValid() != tt.want {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserManager_ValidatePasswordRequireNumber(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: false,
		RequiresSpecial: false,
		MinimumSize:     8,
		RequiresNumber:  true,
		AllowsSpaces:    true,
		AllowedSpecials: "@$!%*#?&",
	}

	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want bool
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: false,
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: false,
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: false,
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: true,
		},
		{
			name: "lower and caps and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: false,
		},
		{
			name: "lower and caps and space",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); got.IsValid() != tt.want {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserManager_ValidatePasswordDoNotAllowSpaces(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: false,
		RequiresSpecial: false,
		MinimumSize:     8,
		RequiresNumber:  false,
		AllowsSpaces:    false,
		AllowedSpecials: "@$!%*#?&",
	}

	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want bool
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: false,
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: true,
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: true,
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: true,
		},
		{
			name: "lower and caps and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: true,
		},
		{
			name: "lower and caps and space",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); got.IsValid() != tt.want {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserManager_ValidatePassword(t *testing.T) {
	manager := Get()
	manager.AuthorizationContext = authorization_context.WithDefaultAuthorization()
	manager.AuthorizationContext.Options.PasswordRules = authorization_context.PasswordRules{
		RequiresCapital: true,
		RequiresSpecial: true,
		MinimumSize:     8,
		RequiresNumber:  true,
		AllowsSpaces:    false,
		AllowedSpecials: "@$!%*#?&",
	}
	type args struct {
		password string
	}
	tests := []struct {
		name string
		um   *UserManager
		args args
		want PasswordValidationResult
	}{
		{
			name: "small",
			um:   manager,
			args: args{
				password: "mypass",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingCapital,
					MissingSpecial,
					MissingNumber,
					InvalidMinimumSize,
				},
			},
		},
		{
			name: "all lower",
			um:   manager,
			args: args{
				password: "mylongpassword",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingCapital,
					MissingSpecial,
					MissingNumber,
				},
			},
		},
		{
			name: "lower and caps",
			um:   manager,
			args: args{
				password: "myLongpassword",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingSpecial,
					MissingNumber,
				},
			},
		},
		{
			name: "lower and caps and numbers",
			um:   manager,
			args: args{
				password: "myLongpassword1",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingSpecial,
				},
			},
		},
		{
			name: "lower and caps and special",
			um:   manager,
			args: args{
				password: "myLongpassword!",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingNumber,
				},
			},
		},
		{
			name: "lower and caps and space",
			um:   manager,
			args: args{
				password: "my Long password",
			},
			want: PasswordValidationResult{
				Errors: []PasswordValidationErrorType{
					MissingSpecial,
					MissingNumber,
					ContainsDisallowedSpace,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.um.ValidatePassword(tt.args.password); !reflect.DeepEqual(got.Errors, tt.want.Errors) {
				t.Errorf("UserManager.ValidatePassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
