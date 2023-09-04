cmake_minimum_required(VERSION 3.26)
project(Ghost)

set(CMAKE_C_STANDARD 11)

add_executable(Ghost main.c
        utils.c
        utils.h
        stdafx.h)
