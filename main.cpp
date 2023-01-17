#include <iostream>
#include <functional>
#include <type_traits>
#include <tuple>
#include <vector>
#include <string>
#include <stdexcept>
#include <map>

namespace detail
{
template<size_t ... Ints>
struct IndexSeq {};

template<size_t Offset, size_t N, size_t ... M>
struct MakeIndexSeqHelper : MakeIndexSeqHelper<Offset, N - 1, N - 1, M...> {};

template<size_t Offset, size_t ... M>
struct MakeIndexSeqHelper<Offset, 0, M...> : IndexSeq<Offset + M...> {};

template<size_t ... Ints>
IndexSeq<Ints...> make_index_seq_helper(IndexSeq<Ints...> seq);

template<size_t N, size_t Offset = 0>
using MakeIndexSeq = decltype(make_index_seq_helper(MakeIndexSeqHelper<Offset, N>{}));

template<typename T>
struct Tag {};

template<typename Tuple, typename Index>
struct TupleCollect;

template<typename Tuple, size_t ... Ints>
struct TupleCollect<Tuple, IndexSeq<Ints...>>
{
    using type = std::tuple<typename std::tuple_element<Ints, Tuple>::type...>;
};

template<typename Tuple, size_t N, size_t Offset = 0>
using TupleCat = TupleCollect<Tuple, MakeIndexSeq<N, Offset>>;

template<typename T>
struct FunctionTraits : FunctionTraits<decltype(&T::operator())> {};

template<typename R, typename ... Args>
struct FunctionTraits<R(Args...)>
{
    using return_type = R;
    using args_type = std::tuple<Args...>;
};

template<typename R, typename ... Args>
struct FunctionTraits<R(*)(Args...)> : FunctionTraits<R(Args...)> {};

template<typename R, typename C, typename ... Args>
struct FunctionTraits<R(C::*)(Args...)> : FunctionTraits<R(Args...)> {};

template<typename R, typename C, typename ... Args>
struct FunctionTraits<R(C::*)(Args...) const> : FunctionTraits<R(Args...)> {};

template<typename F, typename Decoder, typename Traits = FunctionTraits<F>>
class ParseFunction
{
public:
    explicit ParseFunction(F&& f) noexcept : _f(std::move(f)) {}

    template<typename Input, typename ... Args>
    typename Traits::return_type operator()(Input&& input, Args&& ... args)
    {
        constexpr size_t ext_args_size = sizeof...(Args);
        constexpr size_t parsed_args_size = std::tuple_size<typename Traits::args_type>::value - ext_args_size;
        using parsed_args_type = typename TupleCat<typename Traits::args_type, parsed_args_size>::type;
        using ext_args_type = typename TupleCat<typename Traits::args_type, ext_args_size, parsed_args_size>::type;

        static_assert(std::is_same<ext_args_type, std::tuple<Args...>>::value, "ext args must be same");

        Decoder dec;
        dec.init(std::forward<Input>(input), detail::Tag<parsed_args_type>{});
        return call_impl(MakeIndexSeq<parsed_args_size>{}, dec, std::forward<Args>(args)...);
    }
private:
    template<size_t ... Ints, typename ... Args>
    typename Traits::return_type call_impl(IndexSeq<Ints...>, Decoder& dec, Args&& ... args)
    {
        return _f(dec.template as<typename std::tuple_element<Ints, typename Traits::args_type>::type>(Ints)..., std::forward<Args>(args)...);
    }

    F _f;
};

template<typename Input, typename Output, typename Cond>
void split_string(const Input& input, Output& out, Cond cond)
{
    size_t end_pos = 0;
    while (true)
    {
        auto start_pos = input.find_first_not_of(cond, end_pos);
        if (std::string::npos == start_pos)
        {
            break;
        }

        end_pos = input.find_first_of(cond, start_pos);
        if (std::string::npos == end_pos)
        {
            out.emplace_back(input.substr(start_pos));
            break;
        }
        else
        {
            out.emplace_back(input.substr(start_pos, end_pos - start_pos));
        }
    }
}

template<template<typename ...> class L, typename ... Ts>
using ApplyDecay = L<typename std::decay<Ts>::type...>;

template<typename Tuple, typename Arg>
using IsSpecArg = std::integral_constant<
    bool,
    (std::tuple_size<Tuple>::value == 1) 
    && ApplyDecay<std::is_same, Arg, typename std::tuple_element<0, Tuple>::type>::value
>;
}

template<typename Decoder, typename Input, typename ... Args, typename F, typename T = typename std::decay<F>::type>
auto make_parse_function(F&& f) -> std::function<typename detail::FunctionTraits<T>::return_type(Input, Args...)>
{
    return detail::ParseFunction<T, Decoder>{ std::forward<F>(f) };
}

class CommandDecoder
{
public:
    using input_type = std::vector<std::string>;
    using spec_type = input_type;

    template<typename Args>
    void init(input_type&& input, detail::Tag<Args> tag)
    {
        init_tag(std::move(input), std::tuple_size<Args>::value, detail::IsSpecArg<Args, spec_type>{});
    }

    template<typename T>
    T as(size_t index) { return as_tag(index, detail::Tag<T>{}); }

private:
    void init_tag(input_type&& input, size_t arg_size, std::true_type)
    {
        if (arg_size != 1)
        {
            throw std::length_error("bad args length");
        }

        _args = std::move(input);
    }

    void init_tag(input_type&& input, size_t arg_size, std::false_type)
    {
        if (input.size() != arg_size)
        {
            throw std::length_error("bad args length");
        }

        _args = std::move(input);
    }

    const spec_type& as_tag(size_t index, detail::Tag<const spec_type&>)
    {
        if (index != 0)
        {
            throw std::length_error("bad args length");
        }

        return _args;
    }

    std::string as_tag(size_t index, detail::Tag<std::string>)
    {
        return _args[index];
    }

    const std::string& as_tag(size_t index, detail::Tag<const std::string&>)
    {
        return _args[index];
    }

    int as_tag(size_t index, detail::Tag<int>)
    {
        return std::stoi(_args[index]);
    }

    long as_tag(size_t index, detail::Tag<long>)
    {
        return std::stol(_args[index]);
    }

    long long as_tag(size_t index, detail::Tag<long long>)
    {
        return std::stoll(_args[index]);
    }

    unsigned as_tag(size_t index, detail::Tag<unsigned int>)
    {
        return std::stoul(_args[index]);
    }

    unsigned long as_tag(size_t index, detail::Tag<unsigned long>)
    {
        return std::stoul(_args[index]);
    }

    unsigned long long as_tag(size_t index, detail::Tag<unsigned long long>)
    {
        return std::stoull(_args[index]);
    }

    float as_tag(size_t index, detail::Tag<float>)
    {
        return std::stof(_args[index]);
    }

    double as_tag(size_t index, detail::Tag<double>)
    {
        return std::stod(_args[index]);
    }

    long double as_tag(size_t index, detail::Tag<long double>)
    {
        return std::stold(_args[index]);
    }
protected:
    input_type _args;
};

class RawCommandDecoder : public CommandDecoder
{
public:
    using input_type = std::string;

    template<typename Tag>
    void init(input_type&& input, Tag tag)
    {
        std::vector<std::string> args;
        detail::split_string(input, args, " \"[,]");

        CommandDecoder::init(std::move(args), tag);
    }
};

template<
    typename Decoder = CommandDecoder,
    typename Input = typename Decoder::input_type,
    typename Key = std::string,
    typename Command = std::function<void(Input, std::ostream&)>,
    typename Map = std::map<Key, Command>
>
class CommandManager
{
public:
    template<typename F>
    void register_cmd(const Key& cmd, F&& f)
    {
        _cmds[cmd] = make_parse_function<Decoder, Input, std::ostream&>(std::forward<F>(f));
    }

    void call_cmd(const Key& cmd, Input args, std::ostream& out)
    {
        auto it = _cmds.find(cmd);
        if (it == _cmds.end())
        {
            throw std::bad_function_call();
        }

        it->second(std::move(args), out);
    }

private:
    Map _cmds;
};

int main(int argc, const char *argv[])
{
    CommandManager<RawCommandDecoder> m;
    m.register_cmd("test", [](const std::vector<std::string>& args, std::ostream& out) {
        out << std::endl;
    });

    //m.call_cmd("test", { "123", "1.2", "hello" }, std::clog);
    m.call_cmd("test", R"([ "123", "1.2", "hello" ])", std::clog);

    return 0;
}
