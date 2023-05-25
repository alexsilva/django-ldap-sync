from fernet_fieldhasher.fields import FernetPasswordField, FernetPasswordHashField

# legacy: migrations
EncryptedCharField = FernetPasswordField
EncryptedHashField = FernetPasswordHashField
