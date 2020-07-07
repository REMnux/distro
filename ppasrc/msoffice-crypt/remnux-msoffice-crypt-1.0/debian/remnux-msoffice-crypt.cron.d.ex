#
# Regular cron jobs for the remnux-msoffice-crypt package
#
0 4	* * *	root	[ -x /usr/bin/remnux-msoffice-crypt_maintenance ] && /usr/bin/remnux-msoffice-crypt_maintenance
