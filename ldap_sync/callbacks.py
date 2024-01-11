# coding=utf-8
from ldap_sync.logger import user_log_message


def user_active_directory_enabled(user, account, attributes, **kwargs):
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
        if updated:
            qs = user.ldapobject_set.all()
            qs.update(is_active=user.is_active)
            for ldap_object in qs:
                activation_info = "activated" if user.is_active else "deactivated"
                user_log_message(ldap_object, f"The user account has been {activation_info}")
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
