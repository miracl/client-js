import resolve from "@rollup/plugin-node-resolve";

export default {
    input: "src/client.js",
    output: [
        {
            dir: "dist",
            format: "iife",
            indent: false,
            name: "MIRACLTrust"
        },
        {
            file: "cjs/client.cjs",
            format: "cjs"
        }
    ],
    plugins: [resolve()]
};
