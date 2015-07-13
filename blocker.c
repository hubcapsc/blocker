#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#define SYSLOG_NAMES /* needs to be before syslog.h... */
#include <syslog.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <errno.h>

#define M_FAIL "bad value for -m :%s:"
#define N_FAIL "bad value for -n :%s:"
#define BUFSIZE 1024
#define BS1 "/sbin/route add -host "
#define BS2 " reject"

extern char **environ;

/*
 * ssh daemons, and other open-to-the-Internet-doorways, get pounded
 * on with brute force password attacks constantly.
 *
 * A human can spot it in a second by looking at syslog output.
 *
 * grep -i ail /var/log/secure | grep " for " | grep " from "
 *                         ...
 * sshd[3336]: error: PAM: Authentication failure for root from x.y.zz.y
 *                         ...
 * sshd[21338]: Failed keyboard-interactive/pam for invalid user oracle
 *   from blah.blah.blah.blah port 37841 ssh2
 *
 * This program is a syslog scraper that puts rejects into the 
 * routing table for x.y.zz.y and blah.blah.blah.blah when it sees
 * stuff like this happening:
 *
 * route add -host hostname reject
 *
 * The routing table is cleared at reboot, and individual blocked
 * hosts can be unblocked with:
 *
 * route delete -host hostname reject
 *
 */

/*
 * -t ail," for "," from "
 *    is how to communicate the above set of "grep tokens" to this program.
 *
 * If you want to communicate more than one set of "grep tokens" to 
 * target more than one flavor of syslog output, use more than one
 * -t.
 *
 * chain -> suspect -> ail -> " for " -> " from "
 *   |
 *   *-> next -> suspect -> some -> other -> token -> set
 *         |
 *         *-> next -> NULL
 */

struct suspicious_s {
	char *token;
	struct suspicious_s *next;	
};

struct chain_s {
	struct suspicious_s *suspect;
	struct chain_s *next;
};

struct chain_s *process_args(int, char **);
void process_tokens(char *, struct suspicious_s **);
int process_facility(char *);
void process_interesting_line(char *);
void check_line(char *, struct chain_s *);
void block(char *);

char *log_file = NULL;
int bs_len = 0;

/*
 * Default values that can be overridden on the command line.
 */
int facility = LOG_LOCAL1;
int minute_threshold = 5;
int num_fail_threshold = 10;

int main(int argc, char *argv[]) {
	struct chain_s *chain_head;
	struct chain_s *chain_current;
	struct suspicious_s *s;
	FILE *fp;
	char line[BUFSIZE];

	/* This will help us avoid buffer overflows later... */
	bs_len = strlen(BS1) + strlen(BS2);

	/*
	 * We're going to be using environment variables,
	 * and we don't want there to be any except the 
	 * ones we're using...
	 */
	clearenv();

	/* Parse the command line arguments... */
	chain_head = process_args(argc, argv);

	/* Get syslog jumpstarted so that we can make our own logs... */
	openlog(argv[0], LOG_PID, facility);

	syslog(LOG_DEBUG, "blocker started.");

	/* This is the log file we'll be monitoring... */
	if (!(fp = fopen(log_file, "r"))) {
		syslog(LOG_ERR,
		       "%s: can't open log file %s.\n",
		       argv[0],
		       log_file);
		goto out;
	}

	/*
	 * Seek to the end of the to-be-monitored file or
	 * else we'll reprocess the whole thing if this program
	 * is restarted. If we processed the whole file on
	 * startup we'd think all the failures we saw just
	 * happened, possibly blocking hosts we don't want to
	 * block. This program's weltanschauung is "real time",
	 * looking into the past is probably not appropriate...
	 *
	 * Perhaps there should be a flag that lets us process
	 * the whole file on startup... ?
	 */
	fseek(fp, 0, SEEK_END);

	/*
	 * This weird looking I/O loop allows the blocker to
	 * work on growing log files, similar to "tail -f"...
	 * ignore EOF, try again in a second, maybe there's
	 * some now...
	 */
	for (;;) {
		memset(line, 0, BUFSIZE);
		fgets(line, BUFSIZE, fp);
		if (line) 
			check_line(line, chain_head);
		else
			sleep(1);
	}

out:

	closelog();
	return 0;
}

/*
 * Inspect the current line and process it as interesting if
 * it contains all the tokens in one of the token sets...
 */
void check_line(char *line, struct chain_s *chain_head) {
	struct chain_s *chain_current;
	struct suspicious_s *s;
	int interesting = 1;

	chain_current = chain_head;
	while (chain_current) {
		s = chain_current->suspect;
		while (s) {
			if (!strstr(line, s->token)) {
				interesting = 0;
				break;
			}
			s = s->next;
		}

		if (interesting)
			process_interesting_line(line);

		chain_current = chain_current->next;
		interesting = 1;
	}
}

/*
 * OK, now we have a line from the logfile that looks interesting.
 * Try to find the IP address or hostname in the line and see
 * if it needs to be blocked. The code for identifying a 
 * symbolic hostname is kind of heuristic...
 */
void process_interesting_line(char *line) {
	char *word;
	int valid;
	int i;
	struct sockaddr_in sa;
	char *suspect_host = NULL;

	char *host_value = NULL;
	unsigned time_stamp = 0;
	unsigned now = 0;
	int num = 0;
	char buffer[BUFSIZE];
	char **env;
	char *this_var = NULL;
	char *this_host = NULL;

	word = strtok(line, " \n");
	while (word != NULL) {
		if (inet_pton(AF_INET, word, &(sa.sin_addr)) > 0)
			suspect_host = word;
		else if (strchr(word, '.')) {
			valid = 1;
			for (i = 0; word[i] != '\0'; i++) {
				if ((!isalnum(word[i])) &&
				    (word[i] != '.') &&
				    (word[i] != '-'))
					valid = 0;
			}
			if (valid)
				suspect_host = word;
		}
		word = strtok(NULL, " \n");
	}

	if (suspect_host) {
		if (host_value = getenv(suspect_host)) {
			sscanf(host_value, "%u:%d", &time_stamp, &num);
			now = (unsigned)time(NULL);
			if ((now - time_stamp) < minute_threshold * 60) {
				/*
				 * This host has failed before and is
				 * within the time threshold. Block him,
				 * or update his fail count.
				 */
				if (++num > num_fail_threshold) {
					block(suspect_host);
					/*
					 * Don't need this anymore.
					 */
					unsetenv(host_value);
				} else {
					sprintf(buffer,
						"%u:%d",
						time_stamp,
						num);
					setenv(suspect_host, buffer, 1);
					syslog(LOG_DEBUG,
					       "%s: %d fails",
					       suspect_host,
					       num);
				}
			} else {
				/*
				 * This host has failed before, but not
				 * within the time threshold. Re-initialize
				 * his time stamp and fail count.
				 */
				sprintf(buffer, "%u:1", (unsigned)time(NULL));
				setenv(suspect_host, buffer, 1);
				syslog(LOG_DEBUG,
				       "%s: %d fails",
				       suspect_host,
				       1);
			}

		} else {
			/*
			 * Maybe we haven't seen this host before, or
			 * maybe he has failed before, but his demerits
			 * have since timed out.
			 */
			sprintf(buffer, "%u:1", (unsigned)time(NULL));
			setenv(suspect_host, buffer, 1);
			syslog(LOG_DEBUG, "%s: %d fails", suspect_host, 1);

			/*
			 * We can't just go on adding hosts and letting
			 * stale variables sit around cluttering
			 * up environ and slowing things down.
			 * Now is a good time to scan for extant
			 * hosts whose time_stamps are beyond the
			 * threshold.
			 *
			 * Just go on to the next one if we somehow
			 * run into an un-parsable one...
			 */
			for (env = environ; *env; ++env) {
				printf("%s\n", *env);
				this_var = strdup(*env);
				this_host = strtok(this_var, "=");
				if (!this_host)
					continue;
				host_value = getenv(this_host);
				if (!host_value)
					continue;
				sscanf(host_value, "%u:%d", &time_stamp, &num);
				if ((now - time_stamp) >= minute_threshold * 60)
					unsetenv(host_value);
			}
		}
	}
}

void block(char *host) {
	char block_string[BUFSIZE];

	/*
	 * We're building a "route add -host hostname reject" string
	 * here, we've already got the length of the static parts...
	 * Don't want to overflow on some bizarre long hostname...
	 */
	if ((bs_len + strlen(host)) < BUFSIZE) {
		memset(block_string, 0, BUFSIZE);
		strcat(block_string, BS1);
		strcat(block_string, host);
		strcat(block_string, BS2);
		syslog(LOG_DEBUG, "block 'em Danno: %s\n", host);
		system(block_string);
	} else {
		syslog(LOG_ERR, "overflow on %s", host);
	}
}

struct chain_s *process_args(int argc, char *argv[]) {
	int c;
	struct chain_s *chain_head;
	struct chain_s *chain_current;
	struct suspicious_s *suspicious;
	int x;

	if (argc == 1) {
		syslog(LOG_ERR, "%s called with no arguments...\n", argv[0]);
	}

	chain_head = chain_current = calloc(1,sizeof(struct chain_s));

	while ((c = getopt(argc, argv, "tlfmn")) != EOF)
		switch (c) {
			case 't':
				suspicious = NULL;
				process_tokens(argv[optind], &suspicious);
				if (chain_current->suspect) {
					chain_current->next =
					  calloc(1, sizeof(struct chain_s));
					chain_current = chain_current->next;
				}
				if (suspicious)
					chain_current->suspect = suspicious;
			break;

			/*
			 * if we visit 'l' more than once, they must
			 * have specified -l more than once on the
			 * command line which is invalid.
			 */
			case 'l':
				if (log_file)
					log_file = "INVALID";
				else
					log_file = argv[optind];
			break;

			case 'f':
				facility = process_facility(argv[optind]);
			break;

			/*
			 * 'm' = minutes
			 * 'n' = number
			 *
			 * Once a host reaches n fails in m minutes,
			 * that host will be blocked.
			 *
			 */
			case 'm':
				x = strtoimax(argv[optind], NULL, 0);
				if ((!errno) && (x > 0))
					minute_threshold = x;
				else
					syslog(LOG_ERR, M_FAIL, argv[optind]);
			break;

			case 'n':
				x = strtoimax(argv[optind], NULL, 0);
				if ((!errno) && (x > 0))
					num_fail_threshold = x;
				else
					syslog(LOG_ERR, N_FAIL, argv[optind]);
			break;


		}

	/*
	 * Check the grep tokens and log file that were collected
	 * and bail if they don't seem sane. Log a clue as to what
	 * they did wrong.
	 */

	if ((!chain_head->suspect) ||
	    (chain_head->suspect->token[0] == '-')) {
		syslog(LOG_ERR, "command line grep tokens?\n");
		exit(0);
	}

	if ((!log_file) ||
	    (access(log_file, R_OK) == -1)) {
		syslog(LOG_ERR, "command line log file?\n");
		exit(0);
	}

	return chain_head;


}

/*
 * User specified a syslog facility... if the facility name
 * they supplied doesn't make sense, return LOG_LOCAL1.
 */
int process_facility(char *f) {
	int i;
	int f_val = 0;

	for (i = 0; facilitynames[i].c_name; i++)
		if (!strcmp(f, facilitynames[i].c_name))
			f_val = facilitynames[i].c_val;

	if (!f_val)
		f_val = LOG_LOCAL1;

	return(f_val);
}

/* Make a list of this set's grep tokens */
void process_tokens(char *arg, struct suspicious_s **s) {
	char *token;
	struct suspicious_s *this_s;

	if (!arg)
		goto out;

	*s = this_s = calloc(1,sizeof(struct suspicious_s));

	token = strtok(arg, ",");
	while (token != NULL) {
		this_s->token = strdup(token);
		token = strtok(NULL, ",");
		if (token) {
			this_s->next = calloc(1,sizeof(struct suspicious_s));
			this_s = this_s->next;
		}
	}


out:
	return;
}


















