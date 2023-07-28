// swift-tools-version:5.6
 
import PackageDescription
 
let package = Package(
    name: "ObjectivePGP",
    platforms: [
        .iOS(.v11),
        .macOS(.v10_15)
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
