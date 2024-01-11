# coding=utf-8
from ldap_sync.logger import user_log_message


def _user_activation_log(user, queryset):
    for ldap_object in queryset:
        activation_info = "activated" if user.is_active else "deactivated"
        user_log_message(ldap_object, f"The user account has been {activation_info}")


def user_active_directory_enabled(user, account, attributes, **kwargs):
    """
    Activate/deactivate user accounts based on Active Directory's
    userAccountControl flags. Requires 'userAccountControl'
    to be included in LDAP_SYNC_USER_EXTRA_ATTRIBUTES.
    """
    try:
        user_account_control = int(attributes['userAccountControl'])
        qs = user.ldapobject_set.all()

        if user_account_control & 2:
            qs.filter(account=account).update(is_active=False)
        else:
            qs.filter(account=account).update(is_active=True)

        user_is_active = user.is_active
        user.is_active = qs.filter(is_active=True).exists()
        updated = user_is_active != user.is_active

        if updated:
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
        user_is_active = user.is_active
        user.is_active = qs.filter(is_active=True).exists()
        if user_is_active != user.is_active:
            user.save()
            _user_activation_log(user, qs)


def removed_user_delete(user, account):
    """
    Delete user accounts that no longer appear in the
    source LDAP server.
    """
    # ldapobject is removed together with the user.
    user.delete()
