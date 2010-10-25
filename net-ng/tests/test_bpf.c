#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <net-ng/macros.h>
#include <net-ng/bpf.h>

static uint8_t http_payload[] = 
{ 0x00, 0x1d, 0x19, 0x84, 0x9c, 0xdc, 0x00, 0x1e, 0x65, 0x93, 0x1b, 0x6c, 0x08, 
  0x00, 0x45, 0x00, 0x02, 0xa7, 0xa4, 0xb7, 0x40, 0x00, 0x40, 0x06, 0xd7, 0xa0, 
  0xc0, 0xa8, 0x89, 0x69, 0x4a, 0x7d, 0x27, 0x6a, 0xb1, 0x2c, 0x00, 0x50, 0xd9, 
  0xaf, 0x10, 0x24, 0x62, 0x39, 0xb0, 0x04, 0x80, 0x18, 0x00, 0x2e, 0xbe, 0x1d, 
  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x02, 0xb4, 0x98, 0x35, 0x3b, 0xc1, 
  0x37, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 
  0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x77, 0x77, 0x77, 
  0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a, 
  0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x4d, 
  0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2f, 0x35, 0x2e, 0x30, 0x20, 0x28, 0x58, 
  0x31, 0x31, 0x3b, 0x20, 0x55, 0x3b, 0x20, 0x4c, 0x69, 0x6e, 0x75, 0x78, 0x20, 
  0x78, 0x38, 0x36, 0x5f, 0x36, 0x34, 0x3b, 0x20, 0x65, 0x6e, 0x2d, 0x55, 0x53, 
  0x3b, 0x20, 0x72, 0x76, 0x3a, 0x31, 0x2e, 0x39, 0x2e, 0x32, 0x2e, 0x31, 0x30, 
  0x29, 0x20, 0x47, 0x65, 0x63, 0x6b, 0x6f, 0x2f, 0x32, 0x30, 0x31, 0x30, 0x30, 
  0x39, 0x31, 0x35, 0x20, 0x55, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2f, 0x31, 0x30, 
  0x2e, 0x30, 0x34, 0x20, 0x28, 0x6c, 0x75, 0x63, 0x69, 0x64, 0x29, 0x20, 0x46, 
  0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2f, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x30, 
  0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x74, 0x65, 0x78, 
  0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 
  0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, 0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 
  0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 
  0x6e, 0x2f, 0x78, 0x6d, 0x6c, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x39, 0x2c, 0x2a, 
  0x2f, 0x2a, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x38, 0x0d, 0x0a, 0x41, 0x63, 0x63, 
  0x65, 0x70, 0x74, 0x2d, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3a, 
  0x20, 0x65, 0x6e, 0x2d, 0x75, 0x73, 0x2c, 0x65, 0x6e, 0x3b, 0x71, 0x3d, 0x30, 
  0x2e, 0x35, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 
  0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x67, 0x7a, 0x69, 0x70, 0x2c, 
  0x64, 0x65, 0x66, 0x6c, 0x61, 0x74, 0x65, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 
  0x70, 0x74, 0x2d, 0x43, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3a, 0x20, 0x49, 
  0x53, 0x4f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d, 0x31, 0x2c, 0x75, 0x74, 0x66, 
  0x2d, 0x38, 0x3b, 0x71, 0x3d, 0x30, 0x2e, 0x37, 0x2c, 0x2a, 0x3b, 0x71, 0x3d, 
  0x30, 0x2e, 0x37, 0x0d, 0x0a, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41, 0x6c, 0x69, 
  0x76, 0x65, 0x3a, 0x20, 0x31, 0x31, 0x35, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 
  0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x6b, 0x65, 0x65, 0x70, 0x2d, 
  0x61, 0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 
  0x3a, 0x20, 0x50, 0x52, 0x45, 0x46, 0x3d, 0x49, 0x44, 0x3d, 0x32, 0x65, 0x64, 
  0x65, 0x33, 0x35, 0x30, 0x31, 0x61, 0x61, 0x37, 0x31, 0x64, 0x33, 0x31, 0x30, 
  0x3a, 0x55, 0x3d, 0x34, 0x34, 0x37, 0x33, 0x33, 0x34, 0x36, 0x35, 0x30, 0x35, 
  0x31, 0x32, 0x37, 0x65, 0x35, 0x65, 0x3a, 0x54, 0x4d, 0x3d, 0x31, 0x32, 0x38, 
  0x30, 0x38, 0x35, 0x34, 0x34, 0x32, 0x37, 0x3a, 0x4c, 0x4d, 0x3d, 0x31, 0x32, 
  0x38, 0x32, 0x34, 0x30, 0x39, 0x32, 0x37, 0x38, 0x3a, 0x47, 0x4d, 0x3d, 0x31, 
  0x3a, 0x53, 0x3d, 0x50, 0x6b, 0x69, 0x5a, 0x55, 0x5f, 0x4d, 0x61, 0x4e, 0x70, 
  0x7a, 0x4e, 0x7a, 0x42, 0x30, 0x64, 0x3b, 0x20, 0x4e, 0x49, 0x44, 0x3d, 0x33, 
  0x39, 0x3d, 0x41, 0x30, 0x73, 0x4a, 0x51, 0x44, 0x44, 0x30, 0x7a, 0x5f, 0x6a, 
  0x4f, 0x38, 0x4b, 0x4b, 0x65, 0x6d, 0x38, 0x76, 0x36, 0x4e, 0x58, 0x62, 0x4c, 
  0x36, 0x68, 0x5a, 0x67, 0x2d, 0x50, 0x73, 0x4b, 0x6b, 0x50, 0x62, 0x56, 0x30, 
  0x6f, 0x4f, 0x62, 0x51, 0x79, 0x34, 0x41, 0x72, 0x36, 0x76, 0x44, 0x34, 0x51, 
  0x61, 0x31, 0x51, 0x73, 0x73, 0x57, 0x30, 0x69, 0x63, 0x79, 0x76, 0x66, 0x6f, 
  0x78, 0x73, 0x6a, 0x30, 0x33, 0x4f, 0x6c, 0x64, 0x66, 0x65, 0x63, 0x37, 0x64, 
  0x57, 0x5f, 0x34, 0x76, 0x70, 0x4e, 0x67, 0x74, 0x5a, 0x7a, 0x66, 0x2d, 0x63, 
  0x71, 0x78, 0x4c, 0x6d, 0x39, 0x32, 0x37, 0x36, 0x59, 0x78, 0x30, 0x37, 0x55, 
  0x66, 0x5f, 0x5f, 0x59, 0x57, 0x30, 0x55, 0x58, 0x79, 0x59, 0x69, 0x75, 0x56, 
  0x71, 0x6a, 0x5f, 0x77, 0x67, 0x6f, 0x4f, 0x71, 0x45, 0x36, 0x35, 0x61, 0x36, 
  0x0d, 0x0a, 0x0d, 0x0a };

static uint8_t icmp_payload[] =
{ 0x00, 0x1e, 0x65, 0x93, 0x1b, 0x6c, 0x00, 0x1d, 0x19, 0x84, 0x9c, 0xdc, 0x08, 
  0x00, 0x45, 0x00, 0x00, 0x54, 0xdb, 0x46, 0x00, 0x00, 0x38, 0x01, 0x4d, 0x41, 
  0x08, 0x08, 0x08, 0x08, 0xc0, 0xa8, 0x89, 0x69, 0x00, 0x00, 0xce, 0x1a, 0x12, 
  0x2d, 0x00, 0x02, 0xb7, 0xeb, 0xba, 0x4c, 0x00, 0x00, 0x00, 0x00, 0xee, 0xaa, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 
  0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 
  0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };

static const struct option long_options[] = 
{
	{"path", required_argument, 0, 'p'},
	{NULL, 0, 0, 0},
};

static const char short_options[] = "p:h";

static void help(void)
{
	info("	BPF test case\n")
	info("	Options:\n")
	info("		-p	path to HTTP BPF\n")
}

int main (int argc, char ** argv)
{
	struct sock_fprog bpf = { 0 };
	const char * path = NULL;
	int c, opt_idx;
	int rc = EXIT_FAILURE;

	while((c = getopt_long(argc, argv, short_options, long_options, &opt_idx)) != EOF)
	{
		switch (c)
		{
			default:
			case 'h':
				help();
				goto out;
				break;
			case 'p':
				path = strdup(optarg);
				break;
		}
	}
	
	if (path == NULL)
	{
		err("BPF path not specified");
		goto out;
	}

	if (bpf_parse(path, &bpf) == 0)
	{
		err("Error while parsing BPF");
		goto out;
	}

	/* A ICMP packet should not match a HTTP BPF */
	if (bpf_filter(&bpf, icmp_payload, sizeof(icmp_payload)) != 0)
	{
		err("ICMP packet should have matched");
		goto out;
	}

	/* A HTTP packet should match a HTTP BPF */
	if (bpf_filter(&bpf, http_payload, sizeof(http_payload)) == 0)
	{
		err("HTTP packet should have matched");
		goto out;
	}

	info("BPF output check\n");
	bpf_dump_all(&bpf);

	rc = EXIT_SUCCESS;
out:
	return (rc);
}