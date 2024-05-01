# Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character,
# no space, and it must be 8-16 characters long
PASSWORD_REGEXP = r"^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*\W)(?!.* ).{8,16}$"
DATE_REGEXP = r"^(?:(?:19|20)\d{2})-(?:(?:0[1-9]|1[0-2]))-(?:(?:0[1-9]|1\d|2\d|3[01]))$"
