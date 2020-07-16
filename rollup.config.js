import resolve from "@rollup/plugin-node-resolve";

export default {
    input: "src/mfa.js",
    output: {
        dir: "dist",
        format: "iife",
        indent: false,
        name: "Mfa"
    },
    plugins: [resolve()]
};
