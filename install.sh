#!/bin/bash

# Set debug
set -o errexit
set -o nounset

if [ "$(id -u)" != "0" ]; then
  echo "The install script should be run as root" 1>&2
  exit 1
fi

# Check which version this is
wrong_version () {
  echo "This installer is for CentOS 6.4 or Ubuntu 12.04 \"Precise\" and up"
  echo "It is not compatible with your system"
  exit 1
}

if [ -f /etc/redhat-release ]; then
  RH_RELEASE=$(cat /etc/redhat-release)
  DISTRIB_ID=${RH_RELEASE%% *}
  DISTRIB_RELEASE=${RH_RELEASE#*release }
  DISTRIB_RELEASE=${DISTRIB_RELEASE% *}
  if [ $DISTRIB_ID != "CentOS" -a $DISTRIB_ID != "Red" ] || [ "$DISTRIB_RELEASE" '<' "6.4" ]; then
    wrong_version
  fi
  # Import our CentOS/RedHat libraries
  source lib/CentOS/*
else
  LSB_RELEASE=/etc/lsb-release

  if [ ! -f $LSB_RELEASE ]; then
    wrong_version
  fi

  source $LSB_RELEASE || wrong_version

  if [ $DISTRIB_ID != "Ubuntu" ] || [ "$DISTRIB_RELEASE" '<' "12.04" ]; then
    wrong_version
  fi

  # Check we are on a supported Kernel
  KERNEL_UNSUPPORTED_MIN=2.6.30
  KERNEL_UNSUPPORTED_MAX=2.6.39
  KERNEL_VERSION=$(uname -r)

  if [ ! "$KERNEL_VERSION" '<' "$KERNEL_UNSUPPORTED_MIN" ] && [ ! "$KERNEL_VERSION" '>' "$KERNEL_UNSUPPORTED_MAX" ] ; then
    echo "Scalr does not support Linux Kernels $KERNEL_UNSUPPORTED_MIN to $KERNEL_UNSUPPORTED_MAX"
    echo "Please consider upgrading your Kernel."
    exit 1
  fi
  # Import our Ubuntu libraries
  source lib/Ubuntu/*
fi


function valid_ip() {
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Prompt for the server's IP
HOST_IP=${HOST_IP-}
if [ -z "$HOST_IP" ] || ! valid_ip "$HOST_IP" ; then

  echo "Enter an IP for this host that will be accessible from Cloud instances (e.g. this instance's Public IP)"
  echo "Note: You will be able to change this value later"

  invalid_ip=true
  has_errored=false

  while $invalid_ip;
  do
    if $has_errored ; then
      echo "Error: '$HOST_IP' is not a valid IP"
      echo "Hint: if you're unsure, enter 127.0.0.1 and change it later in the configuration file!"
    fi
    read -p "Host IP> " -e HOST_IP
    has_errored=true
    if valid_ip $HOST_IP; then invalid_ip=false; fi
  done

fi

# Import our common libraries
source lib/trap

# Run any pre-install commands
prepare_system


# Add latest PHP repo
echo
echo "======================"
echo "    Installing PHP    "
echo "======================"
echo

install_php_core

# Install common dependencies for PECL packages
echo
echo "================================="
echo "    Installing PHP Extensions    "
echo "================================="
echo

install_php_extension_packages
install_php_extension_pecls

# Disable disabled functions
echo
echo "==========================="
echo "   Changing PHP settings   "
echo "==========================="
echo

configure_php

# Passwords
echo
echo "=========================="
echo "    Creating Passwords    "
echo "=========================="
echo
os_install pwgen

# MySQL root password
ROOT_MYSQL=$(pwgen -s 40)
pre_mysql_install $ROOT_MYSQL

# Securely authenticate to MySQL
MYSQL_CLIENT_FILE=~/$$-root-mysql-client
echo "[client]" > $MYSQL_CLIENT_FILE
chmod 600 $MYSQL_CLIENT_FILE
set +o nounset  # The trap lib uses eval and dynamic variable names
trap_append "rm $MYSQL_CLIENT_FILE" SIGINT SIGTERM EXIT  # Remove the auth file when exiting
set -o nounset
echo "user=root" >> $MYSQL_CLIENT_FILE
echo "password=$ROOT_MYSQL" >> $MYSQL_CLIENT_FILE

# Scalr MySQL user
SCALR_MYSQL_USERNAME=scalr
SCALR_MYSQL_PASSWORD=$(pwgen -s 40)
SCALR_MYSQL_DB=scalr

# Scalr admin user
SCALR_ADMIN_PASSWORD=$(pwgen 20)

# Install MySQL
echo
echo "========================"
echo "    Installing MySQL    "
echo "========================"
echo
os_install mysql-server
post_mysql_install $ROOT_MYSQL
mysql --defaults-extra-file=$MYSQL_CLIENT_FILE --execute="CREATE DATABASE $SCALR_MYSQL_DB;"
mysql --defaults-extra-file=$MYSQL_CLIENT_FILE --execute="GRANT ALL on $SCALR_MYSQL_DB.* to '$SCALR_MYSQL_USERNAME'@'localhost' IDENTIFIED BY '$SCALR_MYSQL_PASSWORD'"


# Install Scalr
echo
echo "========================"
echo "    Installing Scalr    "
echo "========================"
echo
SERVICE_USER=root  # Already exists
WEB_USER=$APACHE_USER
useradd --system $WEB_USER || true  # It should already exist
SCALR_GROUP=scalr  # Needs creation
groupadd --force $SCALR_GROUP  # We don't want this to exist already

for user in $SERVICE_USER $WEB_USER
do
  usermod --append --groups $SCALR_GROUP $user
done

SCALR_REPO=https://github.com/Scalr/scalr.git
SCALR_INSTALL=/var/scalr
SCALR_APP=$SCALR_INSTALL/app
SCALR_SQL=$SCALR_INSTALL/sql
os_install git
git clone $SCALR_REPO $SCALR_INSTALL

pre_python_setup
# We have to be in the correct folder to install.
curr_dir=$(pwd)
cd $SCALR_APP/python
python setup.py install
cd $curr_dir

# We have to create the cache folder
SCALR_CACHE=$SCALR_APP/cache
mkdir --mode=770 $SCALR_CACHE
chown $SERVICE_USER:$SCALR_GROUP $SCALR_CACHE

post_scalr_app_setup

# Configure database
echo
echo "==================================="
echo "    Configuring Scalr Database     "
echo "==================================="
echo
mysql --defaults-extra-file=$MYSQL_CLIENT_FILE --database=$SCALR_MYSQL_DB < $SCALR_SQL/structure.sql
mysql --defaults-extra-file=$MYSQL_CLIENT_FILE --database=$SCALR_MYSQL_DB < $SCALR_SQL/data.sql

# Configure Scalr
echo
echo "=========================="
echo "    Configuring Scalr     "
echo "=========================="
echo

SCALR_LOG_DIR="/var/log/scalr"
SCALR_PID_DIR="/var/run/scalr"
SCALR_ID_FILE=$SCALR_APP/etc/id
SCALR_CONFIG_FILE=$SCALR_APP/etc/config.yml

# Required folders and files
mkdir --mode=775 --parents $SCALR_LOG_DIR $SCALR_PID_DIR
chown $SERVICE_USER:$SCALR_GROUP $SCALR_LOG_DIR $SCALR_PID_DIR

touch $SCALR_ID_FILE
chown $SERVICE_USER:$SCALR_GROUP $SCALR_ID_FILE
chmod 664 $SCALR_ID_FILE

# TODO: Here again, race condition
cat > $SCALR_CONFIG_FILE << EOF
scalr:
  connections:
    mysql: &connections_mysql
      host: 'localhost'
      port: ~
      name: $SCALR_MYSQL_DB
      user: $SCALR_MYSQL_USERNAME
      pass: '$SCALR_MYSQL_PASSWORD'
  ui:
    support_url: 'https://groups.google.com/d/forum/scalr-discuss'
    wiki_url: 'http://wiki.scalr.com'
  email:
    address: "scalr@scalr.mydomain.com"
    name: "Scalr Service"
  pma_instance_ip_address: '127.0.0.1'
  auth_mode: scalr
  instances_connection_policy: auto
  allowed_clouds:
   - ec2
   - openstack
   - cloudstack
   - idcf
   - gce
   - eucalyptus
   - rackspace
   - rackspacenguk
   - rackspacengus
  endpoint:
    scheme: http
    host: '$HOST_IP'
  aws:
    security_group_name: 'scalr.ip-pool'
    ip_pool: ['$HOST_IP/32']
    security_group_prefix: 'scalr.'
  billing:
    enabled: no
    chargify_api_key: ''
    chargify_domain: ''
    emergency_phone_number: ''
  dns:
    mysql:
      host: 'localhost'
      port: ~
      name: 'scalr'
      user: 'scalr'
      pass: 'scalr'
    static:
      enabled: no
      nameservers: ['ns1.example-dns.net', 'ns2.example-dns.net']
      domain_name: 'example-dns.net'
    global:
      enabled: no
      nameservers: ['ns1.example.net', 'ns2.example.net', 'ns3.example.net', 'ns4.example.net']
      default_domain_name: 'provide.domain.here.in'
  load_statistics:
    connections:
      plotter:
        host: 'http://$HOST_IP'
    rrd_dir: '/var/lib/rrdcached/db'
    img_dir: '$SCALR_APP/www/graphics'
    img_url: '/graphics'
EOF

chown $SERVICE_USER:$SCALR_GROUP $SCALR_CONFIG_FILE
chmod 660 $SCALR_CONFIG_FILE

echo
echo "==============================="
echo "    Configuring logging level  "
echo "==============================="
echo
# Configure logging level
SCALR_LOGGING_LEVEL=WARN
sed -ie '/^<root/,/^<.root/ s/level value="[^"]*"/level value="'$SCALR_LOGGING_LEVEL'"/' /var/scalr/app/etc/log4php.xml


# Install Rrdcached
echo
echo "==========================="
echo "    Configuring rrdcached  "
echo "==========================="
echo

configure_rrdcached

mkdir --mode=775 $SCALR_APP/www/graphics/
chown $SERVICE_USER:$SCALR_GROUP $SCALR_APP/www/graphics/

mkdir --mode=775 /var/lib/rrdcached/db/{x1x6,x2x7,x3x8,x4x9,x5x0}
chown $SERVICE_USER:$SCALR_GROUP /var/lib/rrdcached/db/{x1x6,x2x7,x3x8,x4x9,x5x0}

service rrdcached restart

# Install Virtualhost
echo
echo "==========================="
echo "    Configuring Apache     "
echo "==========================="
echo

SCALR_SITE_NAME=scalr
set_apache_vars

cat > $SCALR_SITE_PATH << EOF
<VirtualHost *:80>
ServerName scalr.mydomain.com
ServerAdmin scalr@mydomain.com
DocumentRoot $SCALR_APP/www

<Directory $SCALR_APP/www>
Options -Indexes +FollowSymLinks +MultiViews
AllowOverride All
Order allow,deny
allow from all
$SCALR_APACHE_GRANT
</Directory>

ErrorLog $SCALR_LOG_DIR/scalr-error.log
CustomLog $SCALR_LOG_DIR/scalr-access.log combined
LogLevel warn
</VirtualHost>
EOF

configure_start_apache

# Install crontab
echo
echo "============================="
echo "    Configuring Cronjobs     "
echo "============================="
echo
CRON_FILE=/tmp/$$-scalr-cron  #TODO: Fix insecure race condition on creation here
crontab -u $SERVICE_USER -l > $CRON_FILE.bak || true  # Back up, ignore errors

cat > $CRON_FILE << EOF
* * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --Scheduler
*/5 * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --UsageStatsPoller
*/2 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --Scaling
*/2 * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --SzrMessaging
*/2 * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --BundleTasksManager
*/15 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --MetricCheck
*/2 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --Poller
* * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --DNSManagerPoll
17 5 * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --RotateLogs
*/2 * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --EBSManager
*/20 * * * * /usr/bin/php -q $SCALR_APP/cron/cron.php --RolesQueue
*/5 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --DbMsrMaintenance
*/20 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --LeaseManager
*/1 * * * * /usr/bin/php -q $SCALR_APP/cron-ng/cron.php --ServerTerminate
EOF

crontab -u $SERVICE_USER $CRON_FILE
rm $CRON_FILE

echo
echo "===================================="
echo "    Configuring Daemon Services     "
echo "===================================="
echo

pre_init_setup

INIT_DIR=/etc/init

prepare_init () {
  local daemon_name=$1
  local daemon_desc=$2
  local daemon_pidfile=$3
  local daemon_proc=$4
  local daemon_args=$5


  cat > $INIT_DIR/$daemon_name.conf << EOF
description "$daemon_desc"

start on runlevel [2345]
stop on runlevel [!2345]

respawn
respawn limit 10 5

expect daemon

console none

pre-start script
  if [ ! -r $SCALR_CONFIG_FILE ]; then
    logger -is -t "\$UPSTART_JOB" "ERROR: Config file is not readable"
    exit 1
  fi
  mkdir --mode=775 --parents $SCALR_PID_DIR
  chown $SERVICE_USER:$SCALR_GROUP $SCALR_PID_DIR
end script

exec start-stop-daemon --start --chuid $SERVICE_USER:$SCALR_GROUP --pidfile $daemon_pidfile --exec $daemon_proc -- $daemon_args
EOF
# We can't use setuid / setgid: we need pre-start to run as root.
}

PYTHON=$(command -v python)

# Process "names" for Python scripts (useful later for start-stop-daemon matching)
MSG_SENDER_NAME=msgsender
MSG_SENDER_LOG=$SCALR_LOG_DIR/$MSG_SENDER_NAME.log
MSG_SENDER_PID=$SCALR_PID_DIR/$MSG_SENDER_NAME.pid

DB_QUEUE_NAME=dbqueue
DB_QUEUE_LOG=$SCALR_LOG_DIR/$DB_QUEUE_NAME.log
DB_QUEUE_PID=$SCALR_PID_DIR/$DB_QUEUE_NAME.pid

PLOTTER_NAME=plotter
PLOTTER_LOG=$SCALR_LOG_DIR/$PLOTTER_NAME.log
PLOTTER_PID=$SCALR_PID_DIR/$PLOTTER_NAME.pid

POLLER_NAME=poller
POLLER_LOG=$SCALR_LOG_DIR/$POLLER_NAME.log
POLLER_PID=$SCALR_PID_DIR/$POLLER_NAME.pid

prepare_init "$MSG_SENDER_NAME" "Scalr Messaging Daemon" "$MSG_SENDER_PID" "$PYTHON" "-m scalrpy.msg_sender -p $MSG_SENDER_PID -l $MSG_SENDER_LOG -c $SCALR_CONFIG_FILE -vvv --start"
prepare_init "$DB_QUEUE_NAME" "Scalr DB Queue Event Daeon" "$DB_QUEUE_PID" "$PYTHON" "-m scalrpy.dbqueue_event -p $DB_QUEUE_PID -l $DB_QUEUE_LOG -c $SCALR_CONFIG_FILE -vvv --start"
prepare_init "$PLOTTER_NAME" "Scalr Load Stats Plotter" "$PLOTTER_PID" "$PYTHON" "-m scalrpy.load_statistics -p $PLOTTER_PID -l $PLOTTER_LOG -c $SCALR_CONFIG_FILE --plotter -vvv --start"
prepare_init "$POLLER_NAME" "Scalr Load Stats Poller" "$POLLER_NAME" "$PYTHON" "-m scalrpy.load_statistics -p $POLLER_PID -l $POLLER_LOG -c $SCALR_CONFIG_FILE --poller -vvv --start"

initctl start $MSG_SENDER_NAME
initctl start $DB_QUEUE_NAME
initctl start $PLOTTER_NAME
initctl start $POLLER_NAME

echo
echo "==========================="
echo "    Configuring System     "
echo "==========================="
echo
configure_system

echo
echo "==========================="
echo "    Configuring Users     "
echo "==========================="
echo

HASHED_PASSWORD=$(echo -n $SCALR_ADMIN_PASSWORD | sha256sum | awk '{print $1}')
mysql --defaults-extra-file=$MYSQL_CLIENT_FILE --database=$SCALR_MYSQL_DB \
  --execute="UPDATE account_users SET password='$HASHED_PASSWORD' WHERE id=1"

echo
echo "==========================="
echo "    Validating Install     "
echo "==========================="
echo

CRYPTOKEY_PATH=$SCALR_APP/etc/.cryptokey
touch $CRYPTOKEY_PATH  # TODO: Race condition
chown $SERVICE_USER:$SCALR_GROUP $CRYPTOKEY_PATH
chmod 660 $CRYPTOKEY_PATH

set +o nounset
trap_append "chmod 440 $CRYPTOKEY_PATH" SIGINT SIGTERM EXIT  # Restore ownership of the cryptokey
set -o nounset

for user in $SERVICE_USER $WEB_USER
do
  sudo -u $user php $SCALR_APP/www/testenvironment.php || true # We don't want to exit on an error
done


echo
echo "=============================="
echo "    Done Installing Scalr     "
echo "=============================="
echo

echo "Scalr is installed to:                 $SCALR_INSTALL"
echo "Scalr web is running under user:       $WEB_USER"
echo "Scalr services are running under user: $SERVICE_USER"
echo
echo "==================================="
echo "    Auto-generated credentials     "
echo "==================================="
echo
echo "Passwords have automatically been generated"
echo "MySQL root:$ROOT_MYSQL"
echo "MySQL $SCALR_MYSQL_USERNAME:$SCALR_MYSQL_PASSWORD"
echo
echo "You may log in using the credentials:"
echo "Username: admin"
echo "Password: $SCALR_ADMIN_PASSWORD"

echo
echo "==================================="
echo "    Next steps                     "
echo "==================================="
echo


echo "Configuration"
echo "-------------"
echo "    Some optional modules have not been installed: DNS, LDAP"
echo "    If $HOST_IP is not a valid Public IP for this instance, you must edit your settings in $SCALR_APP/etc/config.yml"
echo

echo "Quickstart Roles"
echo "----------------"
echo "Scalr provides, free of charge, up-to-date role images for AWS"
echo "Those will help you get started with Scalr. To get access:"
echo "    1. Copy the contents of $SCALR_ID_FILE: $(cat $SCALR_ID_FILE)"
echo "    2. Submit them to this form: http://goo.gl/qD4mpa"
echo "    3. Run: \$ php $SCALR_APP/tools/sync_shared_roles.php"

echo "Creating Users"
echo "--------------"
echo "Once logged in as an admin, you will need to create a new user profile to use Scalr"


echo
