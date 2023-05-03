#define _CRT_SECURE_NO_WARNINGS 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

main(int argc, char** argv)
{
	char result[65];
	char path[65] = "D:\\try1.exe";
	sha256_file(path, result);
	printf("The result of sha: %s\n", result);






	{
		char cmd[2048];
		char buf[2048];
		FILE* fp;

		sprintf(cmd, "certUtil -hashfile %s SHA256", path);

#ifdef _WIN32
		if (NULL == (fp = _popen(cmd, "r"))) {
			return (*_errno());
		}
#else
		fprintf(stderr, "Unsupported platform to calculate SHA\n")
			return -1;
#endif

		/* avoid first line - header describing the action */
		if (NULL == fgets(buf, 2048, fp))
			return (*_errno());
		/* get HASH output */
		if (NULL == fgets(buf, 2048, fp))
			return (*_errno());
		printf("by shell: %s\n", buf);
		if (NULL == fgets(buf, 2048, fp) || (NULL == strstr(buf, "successfully")))
			return (*_errno());

		if (_pclose(fp)) {
			fprintf(stderr, "Command not found or exited with error status\n");
			return (*_errno());
		}
	}

}