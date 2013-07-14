# -*- Mode: perl; indent-tabs-mode: nil -*-
#
# The contents of this file are subject to the Mozilla Public
# License Version 1.1 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of
# the License at http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS
# IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
# implied. See the License for the specific language governing
# rights and limitations under the License.
#
# The Original Code is the AntiSpam Bugzilla Extension.
#
# The Initial Developer of the Original Code is Tiago Mello
# Portions created by the Initial Developer are Copyright (C) 2012 the
# Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Tiago Mello <timello@bugzilla.org>

package Bugzilla::Extension::AntiSpam;
use strict;
use base qw(Bugzilla::Extension);

use Bugzilla::Extension::AntiSpam::Util qw(login_to_extern_id
                                           extern_id_to_login);

use Bugzilla::User;
use Bugzilla::Object qw(check_boolean);
use Bugzilla::Util qw(trick_taint trim);
use Scalar::Util qw(blessed);

our $VERSION = '0.01';

BEGIN {
    no warnings 'redefine';
    *Bugzilla::User::is_email_hidden    = sub { $_[0]->{is_email_hidden} ? 1 : 0 };
    *Bugzilla::User::_orig_match_field  = \&Bugzilla::User::match_field;
    *Bugzilla::User::match_field        = \&_user_match_field; 
    *Bugzilla::Bug::_orig_remove_cc     = \&Bugzilla::Bug::remove_cc;
    *Bugzilla::Bug::remove_cc           = \&_bug_remove_cc;
}

sub install_update_db {
    my $dbh = Bugzilla->dbh;
    $dbh->bz_add_column('profiles', 'is_email_hidden',
        { TYPE => 'BOOLEAN', NOTNULL => 1, DEFAULT => 'FALSE' });
}

sub object_columns {
    my ($self, $args) = @_;
    my ($class, $columns) = @$args{qw(class columns)};

    if ($class->isa('Bugzilla::User')) {
        push(@$columns, 'is_email_hidden');
    }
}

sub object_update_columns {
    my ($self, $args) = @_;
    my ($object, $columns) = @$args{qw(object columns)};

    if ($object->isa('Bugzilla::User')) {
        push(@$columns, 'is_email_hidden');
    }
}

sub object_validators {
    my ($self, $args) = @_;
    my ($class, $validators) = @$args{qw(class validators)};

    if ($class->isa('Bugzilla::User')) {
        $validators->{is_email_hidden} = \&Bugzilla::Object::check_boolean;
    }
}

sub template_before_process {
    my ($self, $args) = @_;
    my ($vars, $file) = @$args{qw(vars file)};

    if ($file eq 'bug/process/bugmail.html.tmpl') {
        _filter_bug_process_bugmail($vars);
    }
    elsif ($file eq 'account/prefs/account.html.tmpl') {
        _save_account_username($vars);
    }
    elsif ($file eq 'global/user.html.tmpl') {
        _filter_global_user($vars);
    }
    elsif ($file eq 'flag/list.html.tmpl') {
        _filter_flag_list($vars);
    }
    elsif ($file eq 'attachment/list.html.tmpl') {
        _filter_attachment_list($vars);
    }
    elsif ($file eq 'bug/activity/table.html.tmpl') {
        _filter_bug_activity_table($vars);
    }
    elsif ($file eq 'list/list.html.tmpl') {
        _filter_bug_list($vars);
    }
    elsif ($file eq 'global/confirm-user-match.html.tmpl') {
        _filter_confirm_user_match($vars);
    }
    elsif ($file eq 'request/queue.html.tmpl') {
        _filter_request_queue($vars);
    }
    elsif ($file eq 'account/prefs/email.html.tmpl') {
        _filter_account_prefs_email($vars);
    }
    elsif ($file eq 'email/bugmail-header.txt.tmpl') {
        _filter_email_bugmail_header($vars);
    }
    elsif ($file =~ m{email/bugmail\.(html|txt)\.tmpl}) {
        _filter_bugmail_html_txt($vars);
    }
    elsif ($file eq 'email/flagmail.txt.tmpl') {
        _filter_flagmail($vars);
    }
    elsif ($file eq 'bug/edit.html.tmpl') {
        _filter_bug_edit($vars);
    }
    elsif ($file eq 'global/userselect.html.tmpl') {
        _filter_global_userselect($vars);
    }
    elsif ($file eq 'bug/create/create.html.tmpl') {
        _filter_bug_create($vars);
    }
}

sub webservice {
    my ($self, $args) = @_;
    my $dispatch = $args->{dispatch};

    $dispatch->{User} = 'Bugzilla::Extension::AntiSpam::WebService::User';
}

sub user_preferences {
    my ($self, $args) = @_;

    my ($vars, $save_changes, $current_tab, $handled) =
      @$args{qw(vars save_changes current_tab handled)};

    return unless $current_tab eq 'email';

    my $params = Bugzilla->input_params;

    if ($params->{watched_by_you}) {
        my $dbh = Bugzilla->dbh;
 
        my @watched_by_you = map { $dbh->quote($_) }
            $params->{watched_by_you};
 
        my $sql_in = $dbh->sql_in('extern_id', \@watched_by_you);
 
        my $watched_by_you = $dbh->selectcol_arrayref('
            SELECT login_name
            FROM profiles
            WHERE ' . $dbh->sql_in('extern_id', \@watched_by_you) .
             ' OR ' . $dbh->sql_in('login_name', \@watched_by_you));
 
        $params->{watched_by_you} = $watched_by_you;

        # We don't set $$handle = 1 because we want to enter
        # in the email SWITCH case.
    }
}

###########
# Filters #
###########

sub _filter_bug_process_bugmail {
    my ($vars) = @_;

    my @sent;
    foreach my $email (@{ $vars->{sent_bugmail}->{sent} || [] }) {
        push @sent, login_to_extern_id($email);
    }
    $vars->{sent_bugmail}->{sent} = \@sent;

    my @excluded;
    foreach my $email (@{ $vars->{sent_bugmail}->{excluded} || [] }) {
        push @excluded, login_to_extern_id($email);
    }
    $vars->{sent_bugmail}->{excluded} = \@excluded;
}

sub _filter_global_user {
    my ($vars) = @_;

    return if !blessed $vars->{who};

    $vars->{who}->{login_name} = $vars->{who}->extern_id
        if $vars->{who}->is_email_hidden;
    my ($login) = $vars->{who}->identity =~ /<(.+)>/;
    $login = login_to_extern_id($login);
    $vars->{who}->{identity} =~ s/<.+>/<$login>/;
}

sub _filter_flag_list {
    my ($vars) = @_;

    foreach my $flag_type (@{ $vars->{flag_types} || [] }) {
        foreach my $flag (@{ $flag_type->{flags} || [] }) {
            _filter_flag($flag);
        }
    }
}

sub _filter_attachment_list {
    my ($vars) = @_;

    foreach my $attach (@{ $vars->{attachments} || [] }) {
        foreach my $flag (@{ $attach->flags || [] }) {
            _filter_flag($flag);
        }
    }
}

sub _filter_flag {
    my ($flag) = @_;

    my $setter = $flag->setter;
    if ($setter) {
        $setter->{login_name} =
            $setter->is_email_hidden ? $setter->extern_id
                                     : $setter->email;
    }
    my $requestee = $flag->requestee;
    if ($requestee) {
        $requestee->{login_name} =
            $requestee->is_email_hidden ? $requestee->extern_id
                                        : $requestee->email;
    }
}

sub _filter_bug_activity_table {
    my ($vars) = @_;

    foreach my $op (@{ $vars->{operations} || [] }) {
        $op->{who} = login_to_extern_id($op->{who});
        foreach my $change (@{ $op->{changes} || [] }) {
            my $field_name = $change->{fieldname};
            if (grep { $field_name eq $_ } qw(assigned_to qa_contact cc)) {
                my @added   = split(/[,; ]+/, $change->{added});
                my @removed = split(/[,; ]+/, $change->{removed});

                @added   = map { login_to_extern_id($_) } @added;
                @removed = map { login_to_extern_id($_) } @removed;

                $change->{added}   = join(', ', @added);
                $change->{removed} = join(', ', @removed);
            }
            elsif ($field_name eq 'flagtypes.name') {
                my $added   = $change->{added};
                my $removed = $change->{removed};

                my ($login) = $added =~ /\((.+)\)/;
                $login = login_to_extern_id($login);
                $added =~ s/\(.+\)/($login)/;
                $change->{added} = $added;

                ($login) = $removed =~ /\((.+)\)/;
                $login = login_to_extern_id($login);
                $removed =~ s/\(.+\)/($login)/;
                $change->{removed} = $removed;
            }
        }
    }
}

sub _filter_bug_list {
    my ($vars) = @_;

    foreach my $desc (@{ $vars->{search_description} || [] }) {
        foreach my $field (qw(reporter assigned_to qa_contact)) {
            $desc->{value} = login_to_extern_id($desc->{value})
                if $desc->{field} eq $field;
        }
    }

    foreach my $bug (@{ $vars->{bugs} || [] }) {
        foreach my $field (qw(reporter assigned_to qa_contact)) {
            $bug->{$field} = login_to_extern_id($bug->{$field})
                if defined $bug->{$field};
        }
    }
}

sub _filter_confirm_user_match {
    my ($vars) = @_;

    foreach my $field_matches (values %{ $vars->{matches} }) {
        foreach my $match (values %$field_matches) {
            foreach my $user (@{ $match->{users} || [] }) {
                $user->{login_name} = login_to_extern_id($user->login);
            }
        }
    }
}

sub _filter_request_queue {
    my ($vars) = @_;

    foreach my $request (@{ $vars->{requests} || [] }) {
        my ($requestee) = $request->{requestee} =~ /<(.+)>/;
        my ($requester) = $request->{requester} =~ /<(.+)>/;
        $requestee = login_to_extern_id($requestee);
        $requester = login_to_extern_id($requester);
        $request->{requestee} =~ s/<.+>/<$requestee>/;
        $request->{requester} =~ s/<.+>/<$requester>/;
    }
}

sub _filter_account_prefs_email {
    my ($vars) = @_;

    foreach my $watcher (@{ $vars->{watchers} || [] }) {
        my ($login) = $watcher =~ /<(.+)>/;
        $login = login_to_extern_id($login);
        $watcher =~ s/<.+>/<$login>/;
    }
  
    foreach my $watched (@{ $vars->{watchedusers} || [] }) {
        $watched = login_to_extern_id($watched);
    }
}

sub _filter_email_bugmail_header {
    my ($vars) = @_;

    # The override below can also override the adressee.
    my %to_user = ( email => $vars->{to_user}->email );
    $vars->{to_user} = \%to_user;

    my $changer = $vars->{changer};
    $changer->{login_name} = login_to_extern_id($changer->login);

    my $assignee = $vars->{bug}->assigned_to; 
    $assignee->{login_name} = login_to_extern_id($assignee->login);
}

sub _filter_bugmail_html_txt {
    my ($vars) = @_;

    foreach my $change (@{ $vars->{diffs} || [] }) {
        $change->{who}->{login_name}
            = login_to_extern_id($change->{who}->{login_name});
        if (grep { $change->{field_name} eq $_ }
            qw(assigned_to qa_contact cc))
        {
            my @old = split(/[,; ]+/, $change->{old});
            my @new = split(/[,; ]+/, $change->{new});
  
            my @new_old;
            foreach my $value (@old) {
                push @new_old, login_to_extern_id($value);
            }
            $change->{old} = join(', ', @new_old);
  
            my @new_new;
            foreach my $value (@new) {
                push @new_new, login_to_extern_id($value);
            }
            $change->{new} = join(', ', @new_new);
        }
        elsif ($change->{field_name} eq 'flagtypes.name') {
            my $new   = $change->{new};
            my $old = $change->{old};

            my ($login) = $new =~ /\((.+)\)/;
            $login = login_to_extern_id($login);
            $new =~ s/\(.+\)/($login)/;
            $change->{new} = $new;

            ($login) = $old =~ /\((.+)\)/;
            $login = login_to_extern_id($login);
            $old =~ s/\(.+\)/($login)/;
            $change->{old} = $old;
        }
    }
}

sub _filter_flagmail {
    my ($vars) = @_;

    my $user = Bugzilla->user;
    $user->{login_name}
        = login_to_extern_id($user->login);
    $vars->{user} = $user;
  
    my $setter = $vars->{flag}->{setter};
    $setter->{login_name}
        = login_to_extern_id($setter->{login_name});
  
    my $requestee = $vars->{flag}->{requestee};
    $requestee->{login_name}
        = login_to_extern_id($requestee->{login_name});
}

sub _filter_bug_edit {
    my ($vars) = @_;

    foreach my $cc (@{ $vars->{bug}->cc || [] }) {
        $cc = login_to_extern_id($cc);
    }
}

sub _filter_global_userselect {
    my ($vars) = @_;

    foreach my $field (qw(requestee requester)) {
        $vars->{value} = login_to_extern_id($vars->{value})
            if $vars->{name} eq $field;
    }
}

sub _filter_bug_create {
    my ($vars) = @_;

    foreach my $comp (@{ $vars->{product}->components }) {
        $comp->default_assignee->{login_name}
            = login_to_extern_id($comp->default_assignee->login);
        if (Bugzilla->params->{useqacontact} and $comp->default_qa_contact) {
            $comp->default_qa_contact->{login_name}
               = login_to_extern_id($comp->default_qa_contact->login);
        }

        foreach my $cc (@{ $comp->initial_cc || [] }) {
            $cc->{login_name} = login_to_extern_id($cc->login);
        }
    }
}

###########
# Helpers #
###########

sub _bug_remove_cc {
    my ($self, $user_or_name) = @_;
    $user_or_name = extern_id_to_login($user_or_name)
        || $user_or_name;
    return $self->_orig_remove_cc($user_or_name);
}

sub _user_match_field {
    my ($fields, $data, $behavior) = @_;

    my $params = $data || Bugzilla->input_params;

    # Pre-process flags.
    foreach my $field (keys %$params) {
        next if $field !~ /^requestee(_type)?-\d+$/;
        next if !$params->{$field};
        my ($value) = split(/[,; ]+/, $params->{$field});

        $params->{$field} = extern_id_to_login($value)
          || $value;
    }

    # Pre-process the field data looking for usernames. If a value
    # matches with a valid username, then swap it with the
    # corresponding login email.
    foreach my $field (keys %$fields) {
        next if !$params->{$field};
        if ($fields->{$field}->{type} eq 'multi') {
            my @values
                = ref $params->{$field} ? @{$params->{$field}}
                                        : split(/[,; ]+/, $params->{$field});
            my @logins;
            foreach my $value (@values) {
                my $login = extern_id_to_login($value)
                  || $value;
                push @logins, $login;
            }
            $params->{$field} = join(',', @logins);
        }
        else {
            $params->{$field} =
              extern_id_to_login($params->{$field})
              || $params->{$field};
        }
    }

    Bugzilla::User::_orig_match_field($fields, $params, $behavior);
}

sub _save_account_username {
    my ($vars) = @_;
    my $user = Bugzilla->user;

    if (defined $vars->{changes_saved}) {
        my $params = Bugzilla->input_params;
        my $username = $params->{extern_id};
        my $is_email_hidden = scalar $params->{is_email_hidden};
        $user->set_extern_id($username) if defined $username;
        $user->set('is_email_hidden', $is_email_hidden);
        $user->update();
    }
}

__PACKAGE__->NAME;
