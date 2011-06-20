#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netcore-ng/time.h>

int test_time_add(void)
{
	struct timeval t1, t2, expected, result;

	t1.tv_sec = 1234567;
	t1.tv_usec = 10000;

	t2.tv_sec = 234567;
	t2.tv_usec = 50000;

	expected.tv_sec = 1469134;
	expected.tv_usec = 60000;

	timeval_add(&result, &t1, &t2);

	return (memcmp(&result, &expected, sizeof(result)) == 0);
}

int test_time_subtract(void)
{
	struct timeval before, after, expected, diff;

	before.tv_sec = 1234567;
	before.tv_usec = 10000;

	expected.tv_sec = 10000;
	expected.tv_usec = 0;

	after.tv_sec = before.tv_sec + expected.tv_sec;
	after.tv_usec = before.tv_usec + expected.tv_usec;

	timeval_subtract(&diff, &after, &before);

	return (memcmp(&diff, &expected, sizeof(diff)) == 0);
}

int main(int argc, char ** argv)
{
	assert(argc);
	assert(argv);
	assert(test_time_subtract());
	assert(test_time_add());

	return (EXIT_SUCCESS);
}
