cmake_minimum_required(VERSION 3.25)

project(bare_dns C)

include(bare)

add_bare_module(bare_dns)

target_sources(
  ${bare_dns}
  PRIVATE
    binding.c
)
