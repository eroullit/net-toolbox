INCLUDE_DIRECTORIES (${CMAKE_SOURCE_DIR}/${NET-NG}/include)
LINK_DIRECTORIES (${CMAKE_SOURCE_DIR}/${NET-NG})

ADD_EXECUTABLE(test_pf_sock test_pf_sock.c)
ADD_EXECUTABLE(test_af_sock test_af_sock.c)
ADD_EXECUTABLE(test_af6_sock test_af6_sock.c)
ADD_EXECUTABLE(test_pcap_func test_pcap_func.c)
ADD_EXECUTABLE(test_bpf test_bpf.c)

TARGET_LINK_LIBRARIES (test_pf_sock ${NET-NG})
TARGET_LINK_LIBRARIES (test_af_sock ${NET-NG})
TARGET_LINK_LIBRARIES (test_af6_sock ${NET-NG})
TARGET_LINK_LIBRARIES (test_pcap_func ${NET-NG})
TARGET_LINK_LIBRARIES (test_bpf ${NET-NG})

ENABLE_TESTING()

ADD_TEST(test_pf_sock test_pf_sock)
ADD_TEST(test_af_sock test_af_sock)
ADD_TEST(test_af6_sock test_af6_sock)
ADD_TEST(test_pcap_func test_pcap_func)
ADD_TEST(test_bpf test_bpf -p ${CMAKE_SOURCE_DIR}/bpf/http.bpf)
