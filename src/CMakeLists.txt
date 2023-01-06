aux_source_directory(. SRC) # 存储当前目录下所有源文件
aux_source_directory(./pcap_device PCAP_DEVICE)
aux_source_directory(./net_data NET_DATA)
aux_source_directory(./net_app NET_APP)

add_executable(WebServer ${SRC} ${PCAP_DEVICE} ${NET_DATA} ${NET_APP})

target_link_libraries(WebServer pcap pthread)