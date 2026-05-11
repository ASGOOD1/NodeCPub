from conan import ConanFile
import os
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout

class MyProjectConan(ConanFile):
    name = "pcd_project"
    version = "1.0"
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"
    requires = "pcre2/10.42", "openssl/3.0.10", "sqlite3/3.40.1", "libconfig/1.7.3"
    exports_sources = "src/*"
    
    def layout(self):
        cmake_layout(self)
    
    def generate(self):
        # custom method, can be extended later on
        pass
    
    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
    
    def package(self):
        cmake = CMake(self)
        cmake.install()
    
    def package_info(self):
        self.cpp_info.libs = ["pcd_project"]
