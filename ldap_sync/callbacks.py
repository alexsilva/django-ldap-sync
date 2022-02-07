# coding=utf-8

def user_active_directory_enabled(user, attributes, created, updated):
    """
    Activate/deactivate user accounts based on Active Directory's
    userAccountControl flags. Requires 'userAccountControl'
    to be included in LDAP_SYNC_USER_EXTRA_ATTRIBUTES.
    """
    try:
        user_account_control = int(attributes['userAccountControl'])
        if user_account_control & 2:
            updated = user.is_active
            user.is_active = False
        else:
            updated = not user.is_active
            user.is_active = True
        return updated  # updated
    except (KeyError, ValueError):
        pass


def removed_user_deactivate(user, account):
    """
    Deactivate user accounts that no longer appear in the
    source LDAP server.
    """
    if user.is_active:
        qs = user.ldapobject_set.all()
        qs.filter(account=account).update(is_active=False)
        user.is_active = qs.filter(is_active=True).exists()
        user.save()


def removed_user_delete(user, account):
    """
    Delete user accounts that no longer appear in the
    source LDAP server.
    """
    # ldapobject is removed together with the user.
    user.delete()
