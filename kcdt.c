/*
 * Copyright (c) 2019 FUJITSU LIMITED. All rights reserved.
 * Author: Guangwen Feng <fenggw-fnst@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>
#include <proc/readproc.h>

#define LOG_FILE	"kcdt.log"
#define DUMP_DIR	"core"

#define INFO	0
#define WARN	1
#define ERR 	2

#define CRIO_USKT	"/var/run/crio/crio.sock"
#define DOCKER_USKT	"/var/run/docker.sock"

#define CRIO_URL	"http://localhost/containers/%s"
#define DOCKER_URL	"http://localhost/containers/%s/json"

#define K8S_CONTNAME	"io.kubernetes.container.name"
#define K8S_PODUID	"io.kubernetes.pod.uid"
#define K8S_NAMESPACE	"io.kubernetes.pod.namespace"

#define REGEX1	"(/docker|/crio){1}-[a-f0-9]{64}.scope$"
#define REGEX2	"(/docker|/crio){1}/[a-f0-9]{64}$"
#define REGEX3	"/[a-f0-9]{64}$"

static int fd;
static int log_fd;
static long page_size;

struct memstruct {
	char *memory;
	size_t size;
};

static void cleanup(void);

static void init_log(const char *pathname)
{
	log_fd = open(pathname, O_WRONLY | O_APPEND | O_NOFOLLOW);
	if (log_fd == -1 && errno == ENOENT) {
		log_fd = open(pathname,
			      O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW,
			      0644);
	}

	if (log_fd == -1) {
		fprintf(stderr, "open(%s) logfile failed, errno=%d: %s\n",
			pathname, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void loggerf(int level, const char *fmt, ...)
{
	va_list ap;
	char buf[page_size];
	char current_time[20];
	char msg[page_size];
	char type[5];
	time_t tloc;
	struct tm *tm;
	ssize_t wrote;

	va_start(ap, fmt);

	vsprintf(buf, fmt, ap);

	va_end(ap);

	time(&tloc);

	tm = localtime(&tloc);

	if (strftime(current_time, sizeof(current_time), "%F %T", tm) == 0)
		fprintf(stderr, "strftime() returned 0\n");

	switch (level) {
	case INFO:
		strcpy(type, "INFO");
		break;
	case WARN:
		strcpy(type, "WARN");
		break;
	case ERR:
		strcpy(type, "ERR ");
		break;
	}

	memset(msg, 0, sizeof(msg));

	snprintf(msg, sizeof(msg), "%s %s %s\n", type, current_time, buf);

	if (log_fd > 0) {
		wrote = write(log_fd, msg, strlen(msg));
		if (wrote == -1) {
			fprintf(stderr, "Failed to write log, errno=%d: %s\n",
				errno, strerror(errno));
		} else if ((size_t)wrote != strlen(msg)) {
			fprintf(stderr,
				"write log size not match: %d, expected: %d\n",
				wrote, strlen(msg));
		}
	} else {
		fprintf(stderr, "%s\n", msg);
	}

	if (level == ERR) {
		cleanup();
		exit(EXIT_FAILURE);
	}
}

static int safe_open(int level, const char *pathname, int oflags, ...)
{
	va_list ap;
	int ret;
	mode_t mode;

	va_start(ap, oflags);

	mode = va_arg(ap, int);

	va_end(ap);

	ret = open(pathname, oflags, mode);
	if (ret == -1) {
		loggerf(level, "open(%s) failed, errno=%d: %s",
			pathname, errno, strerror(errno));
	}

	return ret;
}

static int safe_close(int level, int fd)
{
	int ret;

	ret = close(fd);
	if (ret == -1) {
		loggerf(level, "close() failed, errno=%d: %s",
			errno, strerror(errno));
	}

	return ret;
}

static int safe_fsync(int level, int fd)
{
	int ret;

	ret = fsync(fd);
	if (fd == -1) {
		loggerf(level, "fsync() failed, errno=%d: %s",
			errno, strerror(errno));
	}

	return ret;
}

static ssize_t safe_read(int level, int strict, int fd, void *buf, size_t sz)
{
	ssize_t ret;

	ret = read(fd, buf, sz);
	if (ret == -1) {
		loggerf(level, "read() failed, errno=%d: %s",
			errno, strerror(errno));
	} else if (strict == 1 && (size_t)ret != sz) {
		loggerf(level, "read() size not match: %d, expected %d",
			ret, sz);
	}

	return ret;
}

static ssize_t safe_write(int level, int strict, int fd, void *buf, size_t sz)
{
	ssize_t ret;
       
	ret = write(fd, buf, sz);
	if (ret == -1) {
		loggerf(level, "write() failed, errno=%d: %s",
			errno, strerror(errno));
	} else if (strict == 1 && (size_t)ret != sz) {
		loggerf(level, "write() size not match: %d, expected %d",
			ret, sz);
	}

	return ret;
}

static int safe_mkdir_p(const char *pathname, mode_t mode)
{
	int ret;
	int i;
	char ppath[PATH_MAX];

	ret = mkdir(pathname, mode);
	if (ret == -1 && errno == EEXIST) {
		struct stat sb;
		if (stat(pathname, &sb)) {
			loggerf(ERR, "stat(%s) failed, errno=%d: %s",
				pathname, errno, strerror(errno));
		}

		if (!S_ISDIR(sb.st_mode)) {
			loggerf(ERR, "%s exists but is not directory",
				pathname);
		}
	} else if (ret == -1 && errno == ENOENT) {
		for (i = strlen(pathname) - 2; i > 0; i--) {
			if (*(pathname + i) == '/' &&
			    *(pathname + i - 1) != '/')
				break;
		}

		snprintf(ppath, i + 1, "%s", pathname);

		safe_mkdir_p(ppath, mode);

		safe_mkdir_p(pathname, mode);
	} else if (ret == -1) {
		loggerf(ERR, "mkdir(%s) failed, errno=%d: %s",
			pathname, errno, strerror(errno));
	}

	return ret;
}

static ssize_t safe_readlink(int level, int strict, const char *path,
			      char *buf, size_t bufsize)
{
	ssize_t ret;

	ret = readlink(path, buf, bufsize);
	if (ret == -1) {
		if (!strict && errno == ENOENT) {
			ret = 0;
		} else {
			loggerf(level, "readlink() failed, errno=%d: %s",
				errno, strerror(errno));
			return ret;
		}
	}

	if ((size_t)ret < bufsize)
		buf[ret] = '\0';
	else
		buf[bufsize - 1] = '\0';

	return ret;
}

static char *get_dirname(char *pathname, char *res)
{
	char *pos;
	char c;

	strcpy(res, pathname);

	pos = res + strlen(res);
	while (pos != res) {
		c = *(--pos);

		*pos = '\0';

		if (c == '/') {
			if (pos == res)
				*pos = c;

			break;
		}
	}

	return res;
}

static char *get_basename(char *pathname)
{
	char *pos;
	char *res;

	pos = res = pathname;
	while (*pos != '\0') {
		if (*(pos++) == '/')
			res = pos;
	}

	return res;
}

static size_t write_cb(char *contents, size_t size, size_t nmemb, void *data)
{
	size_t wrote;
	char *ptr;
	struct memstruct *mem;

	wrote = size * nmemb;

	mem = (struct memstruct *) data;

	ptr = realloc(mem->memory, mem->size + wrote + 1);
	if (ptr == NULL) {
		loggerf(WARN, "realloc() failed, errno=%d: %s",
			errno, strerror(errno));
		return 0;
	}

	mem->memory = ptr;

	memcpy(&(mem->memory[mem->size]), contents, wrote);

	mem->size += wrote;

	mem->memory[mem->size] = '\0';

	return wrote;
}

static char *do_curl(const char *uskt, const char *url)
{
	CURL *curl;
	CURLcode ret;
	char errbuf[CURL_ERROR_SIZE];
	struct memstruct chunk;

	chunk.memory = malloc(1);
	if (chunk.memory == NULL) {
		loggerf(WARN, "malloc() failed, errno=%d: %s",
			errno, strerror(errno));
		return NULL;
	}
	chunk.size = 0;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (curl == NULL) {
		free(chunk.memory);
		curl_global_cleanup();
		loggerf(WARN, "curl_easy_init() failed");
		return NULL;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);

	if (uskt) {
		curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, uskt);
	} else {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *) &chunk);

	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
	errbuf[0] = 0;

	ret = curl_easy_perform(curl);
	if (ret != CURLE_OK) {
		char buf[page_size];
		if (strlen(errbuf))
			strcpy(buf, errbuf);
		else
			strcpy(buf, curl_easy_strerror(ret));
		free(chunk.memory);
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		loggerf(WARN, "curl_easy_perform() failed, errno=%d: %s",
			ret, buf);
		return NULL;
	}

	curl_easy_cleanup(curl);

	curl_global_cleanup();

	return chunk.memory;
}

static cJSON *getObjectItem_r(const cJSON *object, const char *name)
{
	cJSON *item = NULL;
	cJSON *child = NULL;

	if (cJSON_HasObjectItem(object, name)) {
		item = cJSON_GetObjectItem(object, name);
	} else {
		child = object->child;
		while (1) {
			if (cJSON_IsObject(child) && cJSON_GetArraySize(child) != 0) {
				item = getObjectItem_r(child, name);
				if (item != NULL)
					break;
			}

			if (child->next == NULL)
				break;

			child = child->next;
		}
	}

	return item;
}

static char *parse_json(const char *data, const char *name, char *res)
{
	const char *err;
	const cJSON *item = NULL;
	cJSON *raw = NULL;

	raw = cJSON_Parse(data);
	if (raw == NULL) {
		err = cJSON_GetErrorPtr();

		if (err != NULL) {
			loggerf(WARN, "cJSON_Parse() failed, errno before: %s",
				err);
		}

		return NULL;
	}

	item = getObjectItem_r(raw, name);

	if (!cJSON_IsString(item)) {
		loggerf(WARN, "json value is non-string unexpectedly");
		cJSON_Delete(raw);
		return NULL;
	}

	strcpy(res, item->valuestring);

	cJSON_Delete(raw);

	return res;
}

static int do_grep(const char *data, const char *regex, char *buf, size_t sz)
{
	int ret;
	char errbuf[page_size];
	regex_t preg;
	regmatch_t pmatch[1];

	memset(buf, 0, sz);

	ret = regcomp(&preg, regex, REG_EXTENDED | REG_NEWLINE);
	if (ret) {
		regerror(ret, &preg, errbuf, sizeof(errbuf));
		regfree(&preg);
		loggerf(WARN, "regcomp() failed: %s", errbuf);
		return -1;
	}

	ret = regexec(&preg, data, 1, pmatch, 0);
	if (ret) {
		if (ret == REG_NOMATCH)
			return 1;
		regerror(ret, &preg, errbuf, sizeof(errbuf));
		regfree(&preg);
		loggerf(WARN, "regexec() failed: %s", errbuf);
		return -1;
	}

	regfree(&preg);

	strncpy(buf, &data[pmatch[0].rm_so], pmatch[0].rm_eo - pmatch[0].rm_so);

	return 0;
}

static char *traverse_fd(char *uskt, const pid_t pid, const char *data)
{
	int ret;
	char fddir[20];
	char sym[PATH_MAX];
	char path[PATH_MAX];
	char buf[page_size];
	char sockfd[10];
	char regstr[20];
	char *saveptr;
	DIR *dirp;
	struct dirent *dire;

	snprintf(fddir, sizeof(fddir), "/proc/%d/fd", pid);

	dirp = opendir(fddir);
	if (dirp == NULL) {
		loggerf(WARN, "opendir() failed, errno=%d: %s",
			errno, strerror(errno));
		return NULL;
	}

	while (1) {
		errno = 0;
		dire = readdir(dirp);
		if (dire == NULL) {
			if (errno) {
				loggerf(WARN, "readdir() failed, errno=%d: %s",
					errno, strerror(errno));
			}

			if (closedir(dirp)) {
				loggerf(WARN, "closedir() failed, errno=%d: %s",
					errno, strerror(errno));
			}

			return NULL;
		}

		if (!strcmp(dire->d_name, ".") || !strcmp(dire->d_name, ".."))
			continue;

		snprintf(sym, sizeof(sym), "%s/%s", fddir, dire->d_name);

		if (safe_readlink(WARN, 1, sym, path, sizeof(path)) == -1)
			return NULL;

		ret = do_grep(path, "^socket:\\[[0-9]+]$", buf, sizeof(buf));
		if (ret < 0) {
			loggerf(WARN, "Error occurred when matching socket fd");
			return NULL;
		} else if (ret != 0) {
			continue;
		}

		strtok_r(buf, "[]", &saveptr);

		strcpy(sockfd, strtok_r(NULL, "[]", &saveptr));

		snprintf(regstr, sizeof(regstr), "%s /.*.sock$", sockfd);

		ret = do_grep(data, regstr, buf, sizeof(buf));
		if (ret < 0) {
			loggerf(WARN,
				"Error occurred when matching socket path");
			return NULL;
		} else if (ret != 0) {
			continue;
		}

		strtok_r(buf, " ", &saveptr);

		strcpy(uskt, strtok_r(NULL, " ", &saveptr));

		break;
	}

	if (closedir(dirp)) {
		loggerf(WARN, "closedir() failed, errno=%d: %s",
			errno, strerror(errno));
	}

	return uskt;
}

static int pidof(const char *comm)
{
	PROCTAB *proctab;
	proc_t procinfo;
	pid_t pid = 0;
	char sym[20];
	char path[PATH_MAX];

	memset(&procinfo, 0, sizeof(procinfo));

	proctab = openproc(PROC_FILLCOM | PROC_FILLSTAT);
	if (proctab == NULL) {
		loggerf(WARN, "openproc() failed");
		return -1;
	}

	while (readproc(proctab, &procinfo)) {
		snprintf(sym, sizeof(sym), "/proc/%d/exe", procinfo.XXXID);
		if (safe_readlink(WARN, 0, sym, path, sizeof(path)) == -1) {
			loggerf(WARN, "Error occurred when getting exename");
			closeproc(proctab);
			return -1;
		}

		if (!strcmp(comm, get_basename(path))) {
			pid = procinfo.XXXID;
			break;
		}
	}

	closeproc(proctab);

	return pid;
}

static char *find_uskt(char *uskt, const char *contrt)
{
	int fd;
	pid_t pid;
	ssize_t n;
	size_t len = 0;
	char path[30];
	char buf[page_size];

	if (!strcmp(contrt, "docker")) {
		pid = pidof("dockerd");
		if (pid == 0)
			pid = pidof("dockerd-current");
	} else if (!strcmp(contrt, "crio")) {
		pid = pidof("crio");
	}

	if (pid <= 0) {
		loggerf(WARN, "Failed to get pid of %s", contrt);
		return NULL;
	}

	snprintf(path, sizeof(path), "/proc/%d/net/unix", pid);

	fd = safe_open(WARN, path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
		return NULL;

	while (1) {
		memset(buf, 0, sizeof(buf));

		n = safe_read(WARN, 0, fd, buf, sizeof(buf));
		if (n == -1) {
			safe_close(WARN, fd);
			return NULL;
		}

		if (n == 0)
			break;

		len += n;
	}

	char data[len + len / 10];

	len = 0;

	if (lseek(fd, 0, SEEK_SET) == -1) {
		loggerf(WARN, "lseek() failed, errno=%d: %s",
			errno, strerror(errno));
		safe_close(WARN, fd);
		return NULL;
	}

	while (1) {
		n = safe_read(WARN, 0, fd, &data[len], sizeof(data));
		if (n == -1) {
			safe_close(WARN, fd);
			return NULL;
		}

		if (n == 0)
			break;

		len += n;
	}

	safe_close(WARN, fd);

	if (traverse_fd(uskt, pid, data) == NULL) {
		loggerf(WARN,
			"Failed to traverse /proc/%d/fd to find target socket",
			pid);
		return NULL;
	}

	return uskt;
}

static char *get_uskt(char *uskt, const char *contrt)
{
	struct stat sb;

	if (!strcmp(contrt, "docker")) {
		strcpy(uskt, DOCKER_USKT);
	} else if (!strcmp(contrt, "crio")) {
		strcpy(uskt, CRIO_USKT);
	} else {
		loggerf(WARN, "Unsupported container runtime: %s", contrt);
		return NULL;
	}

	if (stat(uskt, &sb)) {
		if (errno == ENOENT) {
			loggerf(INFO,
				"%s unix socket is not in the default path: %s,"
				"try to find it...", contrt, uskt);
		} else {
			loggerf(WARN, "stat(%s) failed,"
				"try to find the %s unix socket directly...",
				uskt, contrt);
		}

		if (find_uskt(uskt, contrt) == NULL) {
			loggerf(WARN, "Failed to find the %s unix socket",
				contrt);
			return NULL;
		}
	} else {
		if (!S_ISSOCK(sb.st_mode)) {
			loggerf(INFO, "%s is not the %s unix socket,"
				"try to find it...", uskt, contrt);

			if (find_uskt(uskt, contrt) == NULL) {
				loggerf(WARN,
					"Failed to find the %s unix socket",
					contrt);
				return NULL;
			}
		}
	}

	return uskt;
}

static char *get_dumpname(const char *contrt, const char *contid,
			  char *buf, size_t bufsize)
{
	char url[100];
	char uskt[PATH_MAX];
	char *data;
	char contname[page_size];
	char poduid[100];
	char podns[page_size];

	if (!strcmp(contrt, "docker")) {
		snprintf(url, sizeof(url), DOCKER_URL, contid);
	} else if (!strcmp(contrt, "crio")) {
		snprintf(url, sizeof(url), CRIO_URL, contid);
	} else {
		loggerf(WARN, "Unsupported container runtime: %s", contrt);
		return NULL;
	}

	if (get_uskt(uskt, contrt) == NULL) {
		loggerf(WARN, "Failed to get %s unix socket", contrt);
		return NULL;
	}

	data = do_curl(uskt, url);
	if (data == NULL) {
		loggerf(WARN, "Failed to get %s data by curl", contrt);
		return NULL;
	}

	if (parse_json(data, K8S_CONTNAME, contname) == NULL) {
		loggerf(WARN, "Failed to get %s", K8S_CONTNAME);
		free(data);
		return NULL;
	}

	if (parse_json(data, K8S_PODUID, poduid) == NULL) {
		loggerf(WARN, "Failed to get %s", K8S_PODUID);
		free(data);
		return NULL;
	}

	if (parse_json(data, K8S_NAMESPACE, podns) == NULL) {
		loggerf(WARN, "Failed to get %s", K8S_NAMESPACE);
		free(data);
		return NULL;
	}

	free(data);

	snprintf(buf, bufsize, "%s/%s/%s", podns, poduid, contname);

	return buf;
}

static void cleanup(void)
{
	if (fd > 0) {
		safe_fsync(WARN, fd);
		safe_close(WARN, fd);
		fd = 0;
	}

	if (log_fd > 0) {
		safe_fsync(WARN, log_fd);
		safe_close(WARN, log_fd);
		log_fd = 0;
	}
}

int main(int argc, char *argv[])
{
	page_size = getpagesize();

	int opt;
	int coreind;
	int dumpind = 0;
	int logind = 0;
	int i;
	ssize_t ret;
	char path[PATH_MAX];
	char dumpdir[PATH_MAX];
	char selfpath[PATH_MAX];
	char buf[page_size];
	char sbuf[100];
	char cgroup_contents[page_size];
	char *saveptr;
	char contrt[10];
	char contid[70];


	// Check the number of arguments.
	if (argc != 15 && argc != 17 && argc != 19) {
		fprintf(stderr, "Usage: %s [-l LOGFILE] [-d DUMP_DIRECTORY] "
			"-c %%c %%d %%e %%E %%g %%h %%i %%I "
			"%%p %%P %%s %%t %%u\n", argv[0]);

		exit(EXIT_FAILURE);
	}


	// Parse the command-line arguments.
	while ((opt = getopt(argc, argv, "c:d:l:")) != -1) {
		switch (opt) {
		case 'c':
			coreind = optind - 1;
			break;
		case 'd':
			dumpind = optind - 1;
			break;
		case 'l':
			logind = optind - 1;
			break;
		default:
			fprintf(stderr, "Usage: %s [-l LOGFILE] "
				"[-d DUMP_DIRECTORY] -c %%c %%d %%e %%E %%g "
				"%%h %%i %%I %%p %%P %%s %%t %%u\n", argv[0]);

			exit(EXIT_FAILURE);
		}
	}


	// Initialize logfile.
	safe_readlink(ERR, 1, "/proc/self/exe", selfpath, sizeof(selfpath));

	snprintf(path, sizeof(path), "%s/%s",
		 (logind == 0)?get_dirname(selfpath, buf):argv[logind],
		 LOG_FILE);

	init_log(path);


	// Do not dump the coredump handler itself crashes.
	snprintf(path, sizeof(path), "/proc/%s/exe", argv[coreind + 9]);

	safe_readlink(ERR, 1, path, buf, sizeof(buf));

	if (!strcmp(selfpath, buf)) {
		loggerf(WARN, "Stop coredump to avoid recursion");

		cleanup();

		exit(EXIT_SUCCESS);
	}


	// Create dump root directory.
	snprintf(dumpdir, sizeof(dumpdir), "%s/%s",
		 (dumpind == 0)?get_dirname(selfpath, buf):argv[dumpind],
		 DUMP_DIR);

	safe_mkdir_p(dumpdir, 0755);


	// Get the contents of proc/<pid>/cgroup.
	snprintf(path, sizeof(path), "/proc/%s/cgroup", argv[coreind + 9]);

	fd = safe_open(ERR, path, O_RDONLY | O_NOFOLLOW);

	memset(cgroup_contents, 0, sizeof(cgroup_contents));

	safe_read(ERR, 0, fd, cgroup_contents, sizeof(cgroup_contents));

	safe_close(ERR, fd);
	fd = 0;


	// Create sub directory according to k8s related information.
	ret = do_grep(cgroup_contents, REGEX1, buf, sizeof(buf));

	if (ret == 1)
		ret = do_grep(cgroup_contents, REGEX2, buf, sizeof(buf));

	if (ret == 1) {
		ret = do_grep(cgroup_contents, REGEX3, sbuf, sizeof(sbuf));
		if (ret == 0) {
			strcpy(buf, "docker");
			strcat(buf, sbuf);
		}
	}

	if (ret) {
		strcat(dumpdir, "/uncategorized");
	} else {
		strcpy(contrt, strtok_r(buf, "/-.", &saveptr));
		strcpy(contid, strtok_r(NULL, "/-.", &saveptr));

		if (get_dumpname(contrt, contid, path, sizeof(path)) == NULL) {
			strcat(dumpdir, "/uncategorized");
		} else {
			strcat(dumpdir, "/");
			strcat(dumpdir, path);
		}
	}

	time_t rawtime = strtoull(argv[coreind + 11], NULL, 10);

	struct tm *timeinfo = localtime(&rawtime);
	if (timeinfo == NULL)
		loggerf(ERR, "localtime(%%t) failed, error=%d: %s",
			errno, strerror(errno));

	if (strftime(buf, sizeof(buf), "%F-%T", timeinfo) == 0)
		loggerf(ERR, "strftime() returned 0");

	strcat(dumpdir, "/");
	strcat(dumpdir, argv[coreind + 2]);
	strcat(dumpdir, "-");
	strcat(dumpdir, buf);
	strcat(dumpdir, "-");
	strcat(dumpdir, argv[coreind + 9]);

	safe_mkdir_p(dumpdir, 0750);

	loggerf(INFO, "Created %s", dumpdir);


	// Write cgroup file.
	snprintf(path, sizeof(path), "%s/%s", dumpdir, "cgroup");

	fd = safe_open(ERR, path, O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW,
		       0640);

	safe_write(WARN, 1, fd, cgroup_contents, strlen(cgroup_contents));

	safe_fsync(ERR, fd);

	safe_close(ERR, fd);
	fd = 0;


	// Write coredump file.
	snprintf(path, sizeof(path), "%s/%s", dumpdir, "coredump");

	fd = safe_open(ERR, path, O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW,
		       0640);

	while (1) {
		ret = splice(STDIN_FILENO, NULL, fd, NULL, INT_MAX,
			     SPLICE_F_MOVE | SPLICE_F_MORE);
		if (ret == -1) {
			loggerf(ERR, "splice() failed, errno=%d: %s",
				errno, strerror(errno));
		}
		
		if (ret == 0)
			break;
	}

	safe_fsync(ERR, fd);

	safe_close(ERR, fd);
	fd = 0;


	// Write coredump info file.
	char *dumpinfo[] = {
		"core_size_limite",
		"dump_mode",
		"executable_filename",
		"executable_pathname",
		"gid",
		"hostname",
		"tid",
		"global_tid",
		"pid",
		"global_pid",
		"signal",
		"time",
		"uid"
	};

	for (i = 0; i < 13; i++) {
		snprintf(path, sizeof(path), "%s/%s", dumpdir, dumpinfo[i]);

		fd = safe_open(ERR, path,
			       O_WRONLY | O_EXCL | O_CREAT | O_NOFOLLOW, 0640);

		safe_write(WARN, 1, fd, argv[coreind + i],
			   strlen(argv[coreind + i]));

		safe_fsync(ERR, fd);

		safe_close(ERR, fd);
		fd = 0;
	}

	loggerf(INFO, "Dumped in %s", dumpdir);


	// All done, cleanup and exit.
	cleanup();

	exit(EXIT_SUCCESS);
}
