
add_executable( provider provider.cpp )
target_link_libraries( provider ${BOTAN_LIBRARIES} )

add_executable( ecdsa ecdsa.cpp )
target_link_libraries( ecdsa ${BOTAN_LIBRARIES} )

add_executable( aes aes.cpp )
target_link_libraries( aes ${BOTAN_LIBRARIES} )

add_executable( sha256 sha256.cpp )
target_link_libraries( sha256 ${BOTAN_LIBRARIES} )
