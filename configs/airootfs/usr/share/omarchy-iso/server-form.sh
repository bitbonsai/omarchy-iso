# shellcheck shell=bash
# The Omarchy Server questions, sourced by the configurator on a Server ISO
# (omarchy-iso-make --server). It asks, in order: hostname, username, GitHub
# username (whose keys are fetched and confirmed), disk, overwrite confirm,
# whether to encrypt, and the passphrase. There is no user password: the SSH
# key is the only way in and sudo needs no password.
#
# Every prompt returns 0 when answered, OMARCHY_FORM_BACK for Esc and
# OMARCHY_FORM_SIGNAL for Ctrl+C, like the shared setup form.

server_installer_keys=/run/omarchy/installer_authorized_keys
server_claim=/run/omarchy-install.claim

# The machine has a TPM 2.0 the encrypted install can enroll.
server_has_tpm2() {
  [[ $(cat /sys/class/tpm/tpm0/tpm_version_major 2>/dev/null) == 2 ]]
}

# "<type> <fingerprint> <comment>" for one public key, or nothing when it is not one.
server_key_label() {
  local bits fingerprint rest type
  read -r bits fingerprint rest < <(ssh-keygen -lf /dev/stdin <<<"$1" 2>/dev/null) || return 1
  [[ $fingerprint == SHA256:* ]] || return 1
  type=${rest##*(}
  type=${type%)}
  type=${type,,}
  [[ $type == rsa ]] && type="rsa-$bits"
  rest=${rest% (*}
  [[ $rest == "no comment" ]] && rest=""
  printf '%-10s %s %s' "$type" "$fingerprint" "$rest"
}

# Asks for a GitHub username, or a pasted public key, and which of the keys to
# authorize. Sets server_keys (one per line) and server_github_user.
server_prompt_keys() {
  local input status fetched key label source picked
  local -a keys rows

  while true; do
    input=$(gum input --value "${server_github_user:-}" --placeholder "$(t server.githubPlaceholder)" \
      --prompt.foreground="#845DF9" --prompt "$(t server.githubPrompt)") && status=0 || status=$?
    ((status == 0)) || return $status
    input=${input#"${input%%[![:space:]]*}"}
    input=${input%"${input##*[![:space:]]}"}

    if [[ $input =~ ^(ssh-|ecdsa-|sk-) ]]; then
      fetched=$input
      source=$(t server.keysPasted)
    elif [[ $input =~ ^[A-Za-z0-9](-?[A-Za-z0-9]){0,38}$ ]]; then
      notice "$(t server.keysFetching "$input")" 0.1
      fetched=$(curl -fsSL --max-time 10 "https://github.com/$input.keys" 2>/dev/null) || fetched=""
      if [[ -z $fetched ]]; then
        notice "$(t server.keysNone "$input")" 2
        continue
      fi
      server_github_user=$input
      source="github.com/$input"
    else
      notice "$(t server.keyInvalid)" 2
      continue
    fi

    keys=()
    rows=()
    while IFS= read -r key; do
      key=${key%$'\r'}
      label=$(server_key_label "$key") || continue
      rows+=("$label"$'\t'"${#keys[@]}")
      keys+=("$key")
    done <<<"$fetched"
    if ((${#keys[@]} == 0)); then
      notice "$(t server.keyInvalid)" 2
      continue
    fi

    picked=$(gum choose --no-limit --selected="*" --label-delimiter $'\t' \
      --header "$(t server.keysHeader "$source")" "${rows[@]}") && status=0 || status=$?
    # Esc on the list goes back to the username, not out of the form.
    ((status == OMARCHY_FORM_BACK)) && continue
    ((status == 0)) || return $status
    if [[ -z $picked ]]; then
      notice "$(t server.keysRequired)" 2
      continue
    fi

    server_keys=""
    while read -r key; do
      server_keys+="${keys[$key]}"$'\n'
    done <<<"$picked"
    return 0
  done
}

server_account_form() {
  step "$(t server.accountIntro)"
  omarchy_prompt_timezone || return $?
  omarchy_prompt_hostname || return $?
  omarchy_prompt_username || return $?
  server_prompt_keys || return $?
}

# Returns 0 once the account is answered. Esc goes back to the keyboard, as
# on the desktop; Ctrl+C ends the install.
server_account_step() {
  local status
  while true; do
    server_account_form && return 0 || status=$?
    ((status == OMARCHY_FORM_BACK)) || abort
    keyboard_form
  done
}

# Two buttons with "Change disk" in focus. 0 install, 1 pick another disk.
server_confirm_overwrite() {
  local status
  clear_logo
  echo
  say --foreground 1 "$(t server.overwriteWarning "$disk")"
  echo
  gum confirm --default=false --affirmative "$(t server.overwriteYes)" --negative "$(t server.overwriteNo)" \
    "$(t server.overwritePrompt "$disk")" && status=0 || status=$?
  ((status <= 1)) || abort
  return $status
}

server_prompt_passphrase() {
  local status confirmation
  while true; do
    password=$(gum input --password --prompt.foreground="#845DF9" --prompt "$(t server.passphrasePrompt)") && status=0 || status=$?
    ((status == 0)) || return $status
    confirmation=$(gum input --password --prompt.foreground="#845DF9" --prompt "$(t server.passphraseConfirm)") && status=0 || status=$?
    ((status == 0)) || return $status
    if [[ -z $password ]]; then
      notice "$(t server.passphraseBlank)" 1
    elif [[ $password != "$confirmation" ]]; then
      notice "$(t server.passphraseMismatch)" 1
    else
      return 0
    fi
  done
}

# Sets encrypt_installation and, when encrypting, password (the passphrase).
# Esc returns OMARCHY_FORM_BACK so the caller can offer the disks again.
server_encryption_step() {
  local choice status
  while true; do
    clear_logo
    echo
    if server_has_tpm2; then
      say --foreground 8 "$(t server.encryptYesTpm)"
    else
      say --foreground 8 "$(t server.encryptYesNoTpm)"
    fi
    say --foreground 8 "$(t server.encryptNo)"
    echo
    choice=$(gum choose --header "$(t server.encryptHeader)" "$(t common.yes)" "$(t server.no)") && status=0 || status=$?
    ((status == 0)) || return $status

    if [[ $choice == "$(t server.no)" ]]; then
      encrypt_installation=false
      password=""
      return 0
    fi
    encrypt_installation=true
    server_prompt_passphrase && return 0 || status=$?
    ((status == OMARCHY_FORM_BACK)) || return $status
  done
}

# The disk, its overwrite confirm and the encryption question, with Esc on the
# encryption question going back to the disks.
server_disk_step() {
  local status
  while true; do
    disk_form
    server_confirm_overwrite || continue
    server_encryption_step && return 0 || status=$?
    ((status == OMARCHY_FORM_BACK)) || abort
  done
}

# Only one session installs: the console or an SSH login, whichever finishes
# its questions first. mkdir is atomic, so two sessions cannot both win.
server_claim_install() {
  [[ ${1:-} == dry ]] && return 0
  mkdir "$server_claim" 2>/dev/null || abort "$(t server.claimed)"
  printf '%s\n' "${SSH_CONNECTION:-console}" >"$server_claim/owner"
}

# The address and host key lines of the live SSH door, padded like the rest.
server_ssh_lines() {
  local kind value shown=false
  while read -r kind value; do
    case $kind in
      address) say "$(t server.sshAddress "$value")"; shown=true ;;
      hostkey) say --foreground 8 "$(t server.sshHostKey "$value")" ;;
    esac
  done < <(omarchy-installer-ssh status 2>/dev/null)
  $shown || say --foreground 8 "$(t server.sshNoAddress)"
}

# Pressed S on the greeter: authorize keys for the live system, show how to
# reach it, and wait. Exits 3 once an SSH session has claimed the install, so
# the console starts nothing; returns 0 when the user goes back with Esc.
server_ssh_handoff() {
  local status key keys_file
  while true; do
    step "$(t server.sshKeysIntro)"
    server_prompt_keys && break || status=$?
    ((status == OMARCHY_FORM_BACK)) && return 0
    abort
  done

  if [[ ${1:-} == dry ]]; then
    say "[dry] would authorize for root on the live system:"
    say "$server_keys"
    exit 3
  fi
  keys_file=$(mktemp)
  printf '%s' "$server_keys" >"$keys_file"
  omarchy-installer-ssh authorize "$keys_file" >/dev/null || abort
  rm -f "$keys_file"

  while true; do
    clear_logo
    echo
    server_ssh_lines
    echo
    if [[ -d $server_claim ]]; then
      say "$(t server.sshTookOver)"
      exit 3
    fi
    say --foreground 8 "$(t server.sshWaiting)"
    IFS= read -rsn1 -t 2 key </dev/tty || key=""
    [[ $key == $'\e' ]] && return 0
  done
}

# The answers of an unattended install (omarchy-install-unattended), checked
# by the same rules as the prompts: OMARCHY_SERVER_HOSTNAME, _USERNAME, _KEYS
# (public keys, one per line), _DISK (a /dev path) and _ENCRYPT (yes or no),
# with the passphrase on stdin when encrypting. English, a US keyboard, UTC.
server_answers_from_env() {
  local key label
  language=en
  keyboard=us
  keyboard_input_method=none
  keyboard_xkb_layout=""
  timezone=UTC
  hostname=${OMARCHY_SERVER_HOSTNAME:-}
  username=${OMARCHY_SERVER_USERNAME:-}
  disk=${OMARCHY_SERVER_DISK:-}

  [[ $hostname =~ $OMARCHY_HOSTNAME_PATTERN ]] || abort "Not a hostname: '$hostname'"
  [[ $username =~ $OMARCHY_USERNAME_PATTERN && ! $username =~ $OMARCHY_RESERVED_USERNAMES ]] ||
    abort "Not a username this server can have: '$username'"
  [[ -b $disk ]] || abort "Not a disk: '$disk'"

  server_keys=""
  while IFS= read -r key; do
    [[ -n $key ]] || continue
    label=$(server_key_label "$key") || abort "Not an SSH public key: $key"
    server_keys+="$key"$'\n'
  done <<<"${OMARCHY_SERVER_KEYS:-}"
  [[ -n $server_keys ]] || abort "$(t server.keysRequired)"

  case ${OMARCHY_SERVER_ENCRYPT:-} in
    yes)
      encrypt_installation=true
      IFS= read -r password || true
      [[ -n $password ]] || abort "$(t server.passphraseBlank)"
      ;;
    no)
      encrypt_installation=false
      password=""
      ;;
    *) abort "OMARCHY_SERVER_ENCRYPT must be yes or no" ;;
  esac
}

# What the installer reads besides the configuration: the encryption choice,
# the owner (passwordless, sudo on) and the keys for the owner's
# authorized_keys. "*" matches no password, so nobody logs in with one, while
# sshd still lets the owner in with a key, which it would refuse for a locked
# "!" account without PAM.
server_write_user_files() {
  printf '%s\n' "$encrypt_installation" >user_encrypt_installation.txt
  printf '%s' "$server_keys" >authorized_keys

  local encryption_line=""
  if [[ $encrypt_installation == true ]]; then
    encryption_line="    \"encryption_password\": $(printf '%s' "$password" | jq -Rsa),"
  fi
  cat >user_credentials.json <<_EOF_
{
$encryption_line
    "users": [
        {
            "enc_password": "*",
            "groups": [],
            "sudo": true,
            "username": $(printf '%s' "$username" | jq -Rsa)
        }
    ]
}
_EOF_
}
