// swift-tools-version: 5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftDilithium",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "SwiftDilithium",
            targets: ["SwiftDilithium"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
  		.package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  		.package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  		.package(url: "https://github.com/leif-ibsen/Digest", from: "1.12.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SwiftDilithium",
            dependencies: ["BigInt", "ASN1", "Digest"]),
        .testTarget(
            name: "SwiftDilithiumTests",
            dependencies: ["SwiftDilithium"],
            resources: [.copy("Resources/kat44KeyGen.rsp"), .copy("Resources/kat44Sign.rsp"), .copy("Resources/kat44Verify.rsp"),
                        .copy("Resources/kat44HashSign.rsp"), .copy("Resources/kat44HashVerify.rsp"),
                        .copy("Resources/kat65KeyGen.rsp"), .copy("Resources/kat65Sign.rsp"), .copy("Resources/kat65Verify.rsp"),
                        .copy("Resources/kat65HashSign.rsp"), .copy("Resources/kat65HashVerify.rsp"),
                        .copy("Resources/kat87KeyGen.rsp"), .copy("Resources/kat87Sign.rsp"), .copy("Resources/kat87Verify.rsp"),
                        .copy("Resources/kat87HashSign.rsp"), .copy("Resources/kat87HashVerify.rsp")]),
    ]
)
