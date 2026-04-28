#[test_only]
module governance::assertion {

    use std::string;
    use std::vector;
    use aptos_std::debug::print;
    use aptos_std::string_utils;
    use aptos_framework::event;

    public fun assert_eq_with_msg<T: drop + copy>(expected: T, actual: T, msg: vector<u8>) {
        if (expected != actual) {
            if (vector::length(&msg) > 0) {
                print(&string::utf8(msg));
            };

            let expected_str = string::utf8(b"expected: ");
            let actual_str = string::utf8(b"actual: ");

            string::append(&mut expected_str, string_utils::debug_string(&expected));
            string::append(&mut actual_str, string_utils::debug_string(&actual));

            print(&expected_str);
            print(&actual_str);
        };

        assert!(expected == actual, 42);
    }

    /// Asserts that the two values are equal.
    public fun assert_eq<T: drop + copy>(expected: T, actual: T) {
        assert_eq_with_msg(expected, actual, b"");
    }

    /// Asserts that the actual value is true.
    public fun assert_true(actual: bool) {
        assert_eq(true, actual);
    }

    /// Asserts that the actual value is false.
    public fun assert_false(actual: bool) {
        assert_eq(false, actual);
    }

    public fun assert_was_emitted_event<T: drop + store>(e: &T) {
        assert!(event::was_event_emitted(e), 42);
    }
}
