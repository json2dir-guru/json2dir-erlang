#!/usr/bin/env escript
%% json2dir: create the directory tree a JSON document describes, in the current directory.
%% Implements RFC J2D-1. OTP kernel/stdlib only; hand-written JSON parser.
-module(json2dir).
-mode(compile).
-export([main/1]).

main([]) ->
    try
        Input = case file:read_file("/dev/stdin") of
                    {ok, B} -> B;
                    {error, R} -> fail(io_lib:format("cannot read stdin: ~p", [R]))
                end,
        Doc = parse(Input),
        case Doc of
            {obj, _} -> ok;
            _ -> fail("the root of the document must be an object")
        end,
        validate(Doc, <<".">>),
        apply_tree(<<".">>, Doc),
        halt(0)
    catch
        throw:{j2d, Msg} ->
            io:format(standard_error, "json2dir: ~ts~n", [Msg]),
            halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: json2dir < document.json~n", []),
    halt(2).

fail(Msg) -> throw({j2d, iolist_to_binary(Msg)}).

%% ---------------------------------------------------------------- parsing

parse(Bin0) ->
    check_utf8(Bin0),
    Bin = case Bin0 of
              <<16#EF, 16#BB, 16#BF, Rest/binary>> -> Rest;
              _ -> Bin0
          end,
    {V, R1} = value(ws(Bin)),
    case ws(R1) of
        <<>> -> V;
        _ -> fail("input is not valid JSON: trailing data")
    end.

%% <<_/utf8>> rejects overlong forms, surrogates and code points above U+10FFFF.
check_utf8(<<>>) -> ok;
check_utf8(<<_/utf8, R/binary>>) -> check_utf8(R);
check_utf8(_) -> fail("input is not valid UTF-8").

ws(<<C, R/binary>>) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r -> ws(R);
ws(B) -> B.

value(<<${, R/binary>>) -> object(ws(R), []);
value(<<$[, R/binary>>) -> array(ws(R), []);
value(<<$", R/binary>>) -> {S, R1} = string(R, []), {{str, S}, R1};
value(<<"true", R/binary>>) -> {true, R};
value(<<"false", R/binary>>) -> {false, R};
value(<<"null", R/binary>>) -> {null, R};
value(<<C, R/binary>>) when C =:= $-; C >= $0, C =< $9 -> {number, skip_num(R)};
value(_) -> fail("input is not valid JSON").

%% Numbers are never allowed; they are only skipped so validation reports them.
skip_num(<<C, R/binary>>) when C >= $0, C =< $9; C =:= $.; C =:= $e; C =:= $E;
                               C =:= $+; C =:= $- -> skip_num(R);
skip_num(R) -> R.

object(<<$}, R/binary>>, []) -> {{obj, #{}}, R};
object(<<$", R/binary>>, Acc) ->
    {K, R1} = string(R, []),
    case ws(R1) of
        <<$:, R2/binary>> ->
            {V, R3} = value(ws(R2)),
            Acc1 = [{K, V} | Acc],
            case ws(R3) of
                <<$,, R4/binary>> -> object(ws(R4), Acc1);
                %% duplicate names: the last occurrence wins
                <<$}, R4/binary>> -> {{obj, maps:from_list(lists:reverse(Acc1))}, R4};
                _ -> fail("input is not valid JSON: expected , or }")
            end;
        _ -> fail("input is not valid JSON: expected :")
    end;
object(_, _) -> fail("input is not valid JSON: bad object").

array(<<$], R/binary>>, []) -> {{arr, []}, R};
array(B, Acc) ->
    {V, R1} = value(B),
    case ws(R1) of
        <<$,, R2/binary>> -> array(ws(R2), [V | Acc]);
        <<$], R2/binary>> -> {{arr, lists:reverse([V | Acc])}, R2};
        _ -> fail("input is not valid JSON: expected , or ]")
    end.

%% Strings become UTF-8 binaries. Lone surrogates are rejected right away.
string(<<$", R/binary>>, Acc) -> {iolist_to_binary(lists:reverse(Acc)), R};
string(<<$\\, E, R/binary>>, Acc) ->
    case E of
        $" -> string(R, [$" | Acc]);
        $\\ -> string(R, [$\\ | Acc]);
        $/ -> string(R, [$/ | Acc]);
        $b -> string(R, [8 | Acc]);
        $f -> string(R, [12 | Acc]);
        $n -> string(R, [10 | Acc]);
        $r -> string(R, [13 | Acc]);
        $t -> string(R, [9 | Acc]);
        $u ->
            {Cp, R1} = hex4(R),
            if
                Cp >= 16#D800, Cp =< 16#DBFF ->
                    case R1 of
                        <<$\\, $u, R2/binary>> ->
                            {Lo, R3} = hex4(R2),
                            if
                                Lo >= 16#DC00, Lo =< 16#DFFF ->
                                    C = 16#10000 + ((Cp - 16#D800) bsl 10) + (Lo - 16#DC00),
                                    string(R3, [<<C/utf8>> | Acc]);
                                true -> fail("string contains an unpaired surrogate")
                            end;
                        _ -> fail("string contains an unpaired surrogate")
                    end;
                Cp >= 16#DC00, Cp =< 16#DFFF -> fail("string contains an unpaired surrogate");
                true -> string(R1, [<<Cp/utf8>> | Acc])
            end;
        _ -> fail("input is not valid JSON: bad escape")
    end;
string(<<C, _/binary>>, _) when C < 16#20 -> fail("input is not valid JSON: control character in string");
string(<<C, R/binary>>, Acc) -> string(R, [C | Acc]);
string(_, _) -> fail("input is not valid JSON: unterminated string").

hex4(<<A, B, C, D, R/binary>>) ->
    case lists:all(fun is_hex/1, [A, B, C, D]) of
        true -> {list_to_integer([A, B, C, D], 16), R};
        false -> fail("input is not valid JSON: bad \\u escape")
    end;
hex4(_) -> fail("input is not valid JSON: bad \\u escape").

is_hex(C) -> (C >= $0 andalso C =< $9) orelse (C >= $a andalso C =< $f) orelse (C >= $A andalso C =< $F).

%% ---------------------------------------------------------------- validation

validate({str, _}, _) -> ok;
validate({arr, [{str, <<"link">>}, {str, T}]}, Where) ->
    case binary:match(T, <<0>>) of
        nomatch -> ok;
        _ -> fail([Where, ": a link target cannot contain NUL"])
    end;
validate({arr, [{str, <<"script">>}, {str, _}]}, _) -> ok;
validate({arr, _}, Where) ->
    fail([Where, ": an array must be [\"link\", target] or [\"script\", content]"]);
validate({obj, M}, Where) ->
    maps:foreach(
      fun(K, V) ->
              Child = case Where of <<".">> -> K; _ -> <<Where/binary, "/", K/binary>> end,
              check_name(K, Child),
              validate(V, Child)
      end, M);
validate(Other, Where) ->
    fail([Where, io_lib:format(": ~p values are not allowed", [Other])]).

check_name(N, Where) ->
    Bad = N =:= <<>> orelse N =:= <<".">> orelse N =:= <<"..">>
        orelse binary:match(N, [<<"/">>, <<0>>]) =/= nomatch,
    case Bad of
        true -> fail([Where, ": invalid name"]);
        false -> ok
    end.

%% ---------------------------------------------------------------- applying

join(<<".">>, N) -> N;
join(D, N) -> <<D/binary, "/", N/binary>>.

%% lstat: the type of an existing entry (never following a symlink), or none.
lstat(P) ->
    case file:read_link_info(P) of
        {ok, I} -> element(3, I);   % #file_info.type
        {error, enoent} -> none;
        {error, R} -> fail([P, io_lib:format(": ~p", [R])])
    end.

check(_, ok) -> ok;
check(P, {error, R}) -> fail([P, io_lib:format(": ~p", [R])]).

clear(_, none) -> ok;
clear(P, directory) -> fail([P, ": a directory is in the way"]);
clear(P, _) -> check(P, file:delete(P)).

write_file(P, Content, Exec) ->
    case file:open(P, [write, exclusive, raw, binary]) of
        {ok, F} ->
            check(P, file:write(F, Content)),
            check(P, file:close(F)),
            case Exec of
                true ->
                    {ok, I} = file:read_link_info(P),
                    Mode = element(8, I),   % #file_info.mode
                    check(P, file:change_mode(P, (Mode band 8#7777) bor 8#111));
                false -> ok
            end;
        {error, R} -> fail([P, io_lib:format(": ~p", [R])])
    end.

apply_tree(Dir, {obj, M}) ->
    lists:foreach(
      fun({Name, Value}) ->
              P = join(Dir, Name),
              Existing = lstat(P),
              case Value of
                  {str, S} -> clear(P, Existing), write_file(P, S, false);
                  {arr, [{str, <<"link">>}, {str, T}]} ->
                      clear(P, Existing), check(P, file:make_symlink(T, P));
                  {arr, [_, {str, C}]} -> clear(P, Existing), write_file(P, C, true);
                  {obj, _} ->
                      case Existing of
                          directory -> ok;
                          none -> check(P, file:make_dir(P));
                          _ -> check(P, file:delete(P)), check(P, file:make_dir(P))
                      end,
                      apply_tree(P, Value)
              end
      end, lists:sort(maps:to_list(M))).
