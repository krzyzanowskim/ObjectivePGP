// swift-tools-version:5.3
 
import PackageDescription
 
let package = Package(
    name: "ObjectivePGP",
    platforms: [
        .iOS(.v9),
        .macOS(.v10_10)
    ],
    products: [
        .library(
            name: "ObjectivePGP",
            targets: ["ObjectivePGP"]),
    ],
    targets: [
        .binaryTarget(
            name: "ObjectivePGP",
            path: "Frameworks/ObjectivePGP.xcframework"
        )
    ]
)