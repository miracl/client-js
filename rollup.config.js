import resolve from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";

export default [
    {
        input: "src/client.js",
        output: [
            {
                file: "dist/client.js",
                format: "iife",
                indent: false,
                name: "MIRACLTrust"
            },
            {
                file: "dist/client.min.js",
                format: "iife",
                indent: false,
                name: "MIRACLTrust",
                plugins: [terser()]
            },
            {
                file: "cjs/client.cjs",
                format: "cjs"
            }
        ],
        plugins: [resolve()]
    },
    {
        input: "src/promise.js",
        output: [
            {
                file: "dist/client.promise.js",
                format: "iife",
                indent: false,
                name: "MIRACLTrust"
            },
            {
                file: "dist/client.promise.min.js",
                format: "iife",
                indent: false,
                name: "MIRACLTrust",
                plugins: [terser()]
            },
            {
                file: "cjs/promise.cjs",
                format: "cjs"
            }
        ],
        plugins: [resolve()]
    }
];
