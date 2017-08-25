package password_encoder

import (
	"testing"
)

func TestCheckPassword(t *testing.T){
	passworder := PydioPW{
		PBKDF2_HASH_ALGORITHM:"sha256",
		PBKDF2_ITERATIONS  		: 1000,
		PBKDF2_SALT_BYTE_SIZE 	: 24,
		PBKDF2_HASH_BYTE_SIZE 	: 24,
		HASH_SECTIONS 			: 4,
		HASH_ALGORITHM_INDEX 	: 0,
		HASH_ITERATION_INDEX 	: 1,
		HASH_SALT_INDEX 		: 2,
		HASH_PBKDF2_INDEX 		: 3,
	}

	if !passworder.CheckDBKDF2PydioPwd("P@ssw0rd", storePw){
		t.Errorf("eeeeee")
	}
}
const storePw = `sha256:1000:Xx6Kf8nBRb/RnJJvZGMdgricbJFpZQlahrDOeWf/Ycw=:LlCexjaB6aWT3QuYoMz2YdbymCjPFo2V`