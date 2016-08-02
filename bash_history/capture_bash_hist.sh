HISTBASEDIR=/var/log/bashhist

# are we an interactive shell?
if [ "$PS1" ] && [ -d $HISTBASEDIR ]; then


        REALNAME=`who am i | awk '{ print $1 }'`
        EFFNAME=`id -un`
        mkdir -m 700 $HISTBASEDIR/$EFFNAME >/dev/null 2>&1

        shopt -s histappend
        shopt -s lithist
        shopt -s cmdhist

        unset  HISTCONTROL && export HISTCONTROL
        unset  HISTIGNORE && export HISTIGNORE
        export HISTSIZE=10000
        export HISTTIMEFORMAT="%F %T "
        export HISTFILE=$HISTBASEDIR/$EFFNAME/history-$REALNAME
        readonly HISTSIZE HISTTIMEFORMAT HISTFILE


    case $TERM in
    xterm*)
            PROMPT_COMMAND='history -a && printf "\033]0;%s@%s:%s\007" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"'
                ;;
    screen)
            PROMPT_COMMAND='history -a && printf "\033]0;%s@%s:%s\033\\" "${USER}" "${HOSTNAME%%.*}" "${PWD/#$HOME/~}"'
        ;;
    *)
            PROMPT_COMMAND='history -a'
        ;;
      esac
  # Turn on checkwinsize
  shopt -s checkwinsize
  PS1="[\u@\h \W]\\$ "
fi
