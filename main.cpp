#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <memory>

#include <openssl/evp.h>
#include <zlib.h>

#include "unicode.hpp"

class object {
    public:
        virtual ~object(){}
        virtual void print(int indent = 0) const {};
};

class null_object: public object {
    public:
        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << "null";
        }
};

class boolean_object: public object {
    private:
        bool _value;
    public:
        boolean_object(bool value) : _value(value) {}

        inline bool get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class integer_object: public object {
    private:
        int _value;
    public:
        integer_object(std::string value) {
            std::stringstream(value) >> _value;
        }

        inline int get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class real_object: public object {
    private:
        double _value;
    public:
        real_object(std::string value) {
            std::stringstream(value) >> _value;
        }

        inline double get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') <<_value;
        }
};

class string_object: public object {
    private:
        std::string _value;
    public:
        string_object(std::string value): _value(value) {}

        inline const std::string get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _value;
        }
};

class name_object: public string_object {
    public:
        name_object(std::string value): string_object(value) {}
};

class array_object: public object {
    private:
        std::vector<std::shared_ptr<object>> _value;
    public:
        array_object(const std::vector<std::shared_ptr<object>> &value): _value(value) {}

        const std::shared_ptr<object> operator[](std::size_t idx) const {
            return _value[idx];
        }

        void print(int indent = 0) const override {
            std::cout << std::endl;
            std::cout << std::string(indent + 1, ' ') << "[" << std::endl;
            for(auto &elem: _value) {
                elem->print(indent + 2);
                std::cout << std::endl;
            }
            std::cout << std::string(indent + 1, ' ') << "]";
        }
};

class dictionary_object: public object {
    private:
        std::map<std::string, std::shared_ptr<object>> _value;
        std::vector<std::string> _keys;
    public:
        dictionary_object(const std::vector<std::string> &keys, const std::map<std::string, std::shared_ptr<object>> &value)
            : _keys(keys), _value(value) {}

        const std::streamsize get_length() const {
            integer_object *length_value = dynamic_cast<integer_object*>(_value.at("Length").get());
            if(length_value != nullptr) {
                return length_value->get_value();
            }
            return -1;
        }

        const std::shared_ptr<object> operator[](const std::string key) const {
            return _value.at(key);
        }

        const bool isexists(const std::string key) const {
            return _value.count(key) == 1;
        }

        const std::vector<std::string>& get_keys() const {
            return _keys;
        }

        void print(int indent = 0) const override {
            std::cout << std::endl;
            std::cout << std::string(indent + 1, ' ') << "<<" << std::endl;
            for(auto &elem: _keys) {
                std::cout << std::string(indent + 2, ' ') << elem << " : ";
                if(dynamic_cast<dictionary_object*>(_value.at(elem).get())) {
                    _value.at(elem)->print(indent + 2);
                }
                else if(dynamic_cast<array_object*>(_value.at(elem).get())) {
                    _value.at(elem)->print(indent + 2);
                }
                else {
                    _value.at(elem)->print();
                }
                std::cout << std::endl;
            }
            std::cout << std::string(indent + 1, ' ') << ">>" << std::endl;;
        }
};

class indirect_object: public object {
    private:
        int _object_number;
        int _generation_number;
        std::shared_ptr<object> _value;
    public:
        indirect_object(int object_number, int generation_number, std::shared_ptr<object> value)
            : _object_number(object_number), _generation_number(generation_number),
              _value(value) {}

        inline std::shared_ptr<object> get_value() const {
            return _value;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _object_number << " " << _generation_number << " obj" << std::endl;
            _value->print(indent);
        }
};

class indirect_references_object: public object {
    private:
        int _object_number;
        int _generation_number;
    public:
        indirect_references_object(int object_number, int generation_number)
            : _object_number(object_number), _generation_number(generation_number) {}

        int get_object_number() const {
            return _object_number;
        }

        int get_generation_number() const {
            return _generation_number;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << _object_number << " " << _generation_number << " R";
        }
};

class stream_object: public object {
    private:
        dictionary_object _dict;
        std::string _stream;

    public:
        stream_object(const dictionary_object &dict, const std::string &stream)
            : _dict(dict), _stream(stream) {}

        dictionary_object get_dict() const {
            return _dict;
        }

        std::string get_stream() const {
            return _stream;
        }

        void print(int indent = 0) const override {
            std::cout << std::string(indent, ' ') << "stream: " << _stream.size() << " bytes" << std::endl;
            _dict.print(indent);
        }
};

bool is_whitespace(int c)
{
    return c == 0x00 || c == 0x09 || c == 0x0a || c == 0x0c || c == 0x0d || c == 0x20;
}

std::shared_ptr<object> parse_object(std::istream &ss);

std::shared_ptr<object> parse_hexstring(std::istream &ss)
{
    std::string result = "";
    int c = 0;
    int v1 = -1;
    while(ss) {
        c = ss.get();
        if(c == '<') continue;
        if(c == '>') break;
        if(is_whitespace(c)) continue;
        int v;
        if(c >= '0' && c <= '9') {
            v = c - '0';
        }
        else if(c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        }
        else if(c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        }
        else {
            throw std::runtime_error("invalid hexstring");
        }
        if (v1 < 0) {
            v1 = v;
        }
        else {
            result += (v1 << 4) | v;
            v1 = -1;
        }
    }
    if(v1 >= 0) {
        result += (v1 << 4);
    }
    return std::shared_ptr<object>(new string_object(result));
}

std::shared_ptr<object> parse_literal(std::istream &ss)
{
    std::string result = "";
    bool isescape = false;
    bool isescapeCR = false;
    std::string octalstr = "";
    while(ss) {
        char c = ss.get();
        if(isescapeCR && c == 0x0a) {
            isescapeCR = false;
            continue;
        }
        if(!octalstr.empty() && c >= '0' && c <= '7') {
            octalstr += c;
            continue;
        }
        if(!octalstr.empty()) {
            int v = 0;
            for(auto o: octalstr) {
                int v2 = o - '0';
                v = (v << 3) | v2;
            }
            result += v;
            octalstr.clear();
        }
        if(isescape) {
            isescape = false;
            if(c == 'n') {
                c = 0x0a;
            }
            else if(c == 'r') {
                c = 0x0d;
            }
            else if(c == 't') {
                c = 0x09;
            }
            else if(c == 'b') {
                c = 0x08;
            }
            else if(c == 'f') {
                c = 0x0c;
            }
            else if(c == '(') {
                c = 0x28;
            }
            else if(c == ')') {
                c = 0x29;
            }
            else if(c == '\\') {
                c = 0x5c;
            }
            else if(c >= '0' && c <= '7') {
                octalstr += c;
            }
            else if(c == 0x0d) {
                c = 0x0a;
                isescapeCR = true;
            }
            else if(c == 0x0a) {
                c = 0x0a;
            }
        }
        else if(c == '\\') {
            isescape = true;
            continue;
        }
        result += c;
    }
    return std::shared_ptr<object>(new string_object(result.substr(1,result.size()-2)));
}

std::shared_ptr<object> parse_name(std::istream &ss)
{
    char c = ss.get();
    while(c != '/') {
        c = ss.get();
    }
    std::string result = "";
    while(ss) {
        c = ss.get();
        if(is_whitespace(c)) break;
        if(c == '#') {
            c = ss.get();
            int v1;
            if(c >= '0' && c <= '9') {
                v1 = c - '0';
            }
            else if(c >= 'A' && c <= 'F') {
                v1 = c - 'A' + 10;
            }
            else if(c >= 'a' && c <= 'f') {
                v1 = c - 'a' + 10;
            }
            c = ss.get();
            int v2;
            if(c >= '0' && c <= '9') {
                v2 = c - '0';
            }
            else if(c >= 'A' && c <= 'F') {
                v2 = c - 'A' + 10;
            }
            else if(c >= 'a' && c <= 'f') {
                v2 = c - 'a' + 10;
            }
            result += (v1 << 4) | v2;
        }
        else {
            result += c;
        }
    }
    return std::shared_ptr<object>(new name_object(result));
}

std::shared_ptr<object> parse_array(std::stringstream &ss)
{
    ss.seekg(-1, std::ios::end);
    ss << ' ';
    ss.seekg(1, std::ios::beg);
    std::vector<std::shared_ptr<object>> arrayobj;
    while(ss) {
        if(is_whitespace(ss.peek())) {
            ss.get();
        }
        auto obj = parse_object(ss);
        if(obj) {
            arrayobj.push_back(obj);
        }
    }
    return std::shared_ptr<object>(new array_object(arrayobj));
}

std::shared_ptr<object> parse_dictionary(std::stringstream &ss)
{
    ss.seekg(-2, std::ios::end);
    ss << ' ';
    ss << ' ';
    ss.seekg(0, std::ios::beg);
    int count = 2;
    while(ss.get() != '<' || --count > 0);
    std::vector<std::string> keys;
    std::map<std::string, std::shared_ptr<object>> dictobj;
    while(ss) {
        std::shared_ptr<object> key = parse_object(ss);
        std::shared_ptr<object> value = parse_object(ss);
        if(key && value) {
            name_object *name_key = dynamic_cast<name_object*>(key.get());
            if(name_key != nullptr) {
                keys.push_back(name_key->get_value());
                dictobj[name_key->get_value()] = value;
            }
        }
    }
    return std::shared_ptr<object>(new dictionary_object(keys, dictobj));
}

std::shared_ptr<object> parse_indirectobject(std::istream &ss)
{
    std::string str1,str2,str3;
    ss >> str1 >> str2 >> str3;

    int obj_num, gen_num;
    std::stringstream(str1) >> obj_num;
    std::stringstream(str2) >> gen_num;

    auto obj = parse_object(ss);
    if(!obj) throw std::runtime_error("parse error");

    std::string keyword;
    ss >> keyword;
    if(keyword == "stream") {
        if(ss.peek() == 0x0d) {
            ss.ignore(2);
        }
        else {
            ss.ignore();
        }
        std::string stream;
        keyword.clear();
        while(ss) {
            int c = ss.get();
            keyword += c;
            if(keyword.find("endstream") != std::string::npos) {
                stream.push_back(c);
                for(auto k: keyword) {
                    stream.pop_back();
                }
                break;
            }
            else if (keyword.size() > 9){
                keyword = keyword.substr(1);                
            }
            stream.push_back(c);
        }
        const dictionary_object *dict = dynamic_cast<const dictionary_object*>(obj.get());
        auto streamobj = std::shared_ptr<object>(new stream_object(*dict, stream));
        return std::shared_ptr<object>(new indirect_object(obj_num, gen_num, streamobj));
    }
    return std::shared_ptr<object>(new indirect_object(obj_num, gen_num, obj));
}

std::shared_ptr<object> parse_numeric(std::istream &is, std::istream &ss)
{
    std::string object1;
    is >> object1;
    auto pos1 = is.tellg();
    is.seekg(0, std::ios::end);
    ss.seekg(pos1 - is.tellg(), std::ios::cur);
    if(object1.find('.') == std::string::npos) {
        return std::shared_ptr<object>(new integer_object(object1));
    }
    else {
        return std::shared_ptr<object>(new real_object(object1));
    }
}

std::shared_ptr<object> parse_object(std::istream &ss)
{
    enum state {
        array,
        hexstring,
        dictionary,
        literalstring,
        name,
        escape,
        comment,
        stream,
        indirectobject,
        maybeobj,
        maybeobj2,
        maybeobj3,
        numeric
    };

    std::stringstream bs;
    std::vector<state> current_state;
    std::string keyword_buffer;

    while(ss) {
        char c = ss.get();
        // std::cout << c << " " << (current_state.empty() ? -1 : current_state.back()) << std::endl;
        bs << c;

        if (!current_state.empty() && current_state.back() == stream) {
            // std::cout << ss.tellg() << " " << keyword_buffer << std::endl;
            keyword_buffer += c;
            if(c == 'm' && keyword_buffer == "endstream") {
                keyword_buffer.clear();
                current_state.pop_back();
            }
            else if(keyword_buffer.size() >= 9) {
                keyword_buffer = keyword_buffer.substr(1);
            }
        }
        else if (!current_state.empty() && current_state.back() == escape) {
            current_state.pop_back();
        }
        else if (c == '\\') {
            keyword_buffer.clear();
            current_state.push_back(escape);            
        }
        else if (!current_state.empty() && current_state.back() == comment) {
            if(c == '\r') {
                if(ss.peek() == '\n') {
                    c = ss.get();
                    bs << c;
                }
                current_state.pop_back();
            }
            else if (c == '\n') {
                current_state.pop_back();
            }
        }
        else if (!current_state.empty() && current_state.back() == literalstring && c == ')') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_literal(bs);
            }                        
        }
        else if (!current_state.empty() && current_state.back() == literalstring) {
            // ignore spetials
        }
        else if (!current_state.empty() && current_state.back() == numeric && is_whitespace(c)) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && is_whitespace(c)) {
            current_state.back() = maybeobj2;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && c == '.') {
            current_state.back() = numeric;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj && std::string("0123456789").find_first_of(c) == std::string::npos) {
            current_state.pop_back();
        }
        else if (!current_state.empty() && current_state.back() == maybeobj2 && is_whitespace(c)) {
            current_state.back() = maybeobj3;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj2 && std::string("0123456789").find_first_of(c) == std::string::npos) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3 && c == 'R') {
            current_state.pop_back();
            std::string str1,str2,str3;
            std::stringstream(bs.str()) >> str1 >> str2 >> str3;

            int obj_num, gen_num;
            std::stringstream(str1) >> obj_num;
            std::stringstream(str2) >> gen_num;
            return std::shared_ptr<object>(new indirect_references_object(obj_num, gen_num));
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3 && c == 'o') {
            current_state.back() = indirectobject;
        }
        else if (!current_state.empty() && current_state.back() == maybeobj3) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_numeric(bs, ss);
            }
        }
        else if (c == '%') {
            keyword_buffer.clear();
            current_state.push_back(comment);
        }
        else if (c == '[') {
            keyword_buffer.clear();
            current_state.push_back(array);
        }
        else if (!current_state.empty() && current_state.back() == array && c == ']') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_array(bs);
            }
        }
        else if (!current_state.empty() && current_state.back() == hexstring && c == '<') {
            current_state.back() = dictionary;
        }
        else if (c == '<') {
            keyword_buffer.clear();
            current_state.push_back(hexstring);            
        }
        else if (!current_state.empty() && current_state.back() == hexstring && c == '>') {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_hexstring(bs);
            }            
        }
        else if (!current_state.empty() && current_state.back() == dictionary && c == '>') {
            c = ss.get();
            bs << c;

            if(c == '>') {
                current_state.pop_back();
                if(current_state.empty()) {
                    return parse_dictionary(bs);
                }
            }
        }
        else if (c == '(') {
            keyword_buffer.clear();
            current_state.push_back(literalstring);            
        }
        else if (c == '/') {
            keyword_buffer.clear();
            current_state.push_back(name);            
        }
        else if (!current_state.empty() && current_state.back() == name && is_whitespace(c)) {
            current_state.pop_back();
            if(current_state.empty()) {
                return parse_name(bs);
            }
        }
        else if (!current_state.empty() && current_state.back() == indirectobject) {
            if(!is_whitespace(c)) {
                keyword_buffer += c;
            }

            if(keyword_buffer == "endobj") {
                current_state.pop_back();
                return parse_indirectobject(bs);
            }
            if(keyword_buffer == "stream") {
                current_state.push_back(stream);
                keyword_buffer.clear();
            }
        }
        else if (current_state.empty()){
            if(!is_whitespace(c)) {
                keyword_buffer += c;
            }

            if(keyword_buffer == "null") {
                return std::shared_ptr<object>(new null_object());
            }
            if(keyword_buffer == "true") {
                return std::shared_ptr<object>(new boolean_object(true));
            }
            if(keyword_buffer == "false") {
                return std::shared_ptr<object>(new boolean_object(false));
            }

            if(c == '+' || c == '-') {
                current_state.push_back(numeric);
            }
            else if(std::string("0123456789").find_first_of(c) != std::string::npos) {
                current_state.push_back(maybeobj);
            }
        }
    }
    return std::shared_ptr<object>();
}

int check_header(std::ifstream &ifs)
{
    std::string header_buffer;
    std::getline(ifs, header_buffer);

    if (header_buffer == "%PDF-1.0") {
        return 0;
    }
    if (header_buffer == "%PDF-1.1") {
        return 1;
    }
    if (header_buffer == "%PDF-1.2") {
        return 2;
    }
    if (header_buffer == "%PDF-1.3") {
        return 3;
    }
    if (header_buffer == "%PDF-1.4") {
        return 4;
    }
    if (header_buffer == "%PDF-1.5") {
        return 5;
    }
    if (header_buffer == "%PDF-1.6") {
        return 6;
    }
    if (header_buffer == "%PDF-1.7") {
        return 7;
    }
    if (header_buffer == "%PDF-2.0") {
        return 20;
    }
    std::cerr << header_buffer << std::endl;
    return -1;
}

std::streamoff get_startxref_pos(std::ifstream &ifs)
{
    ifs.seekg(-6, std::ios::end);
    std::string eofmarker_buffer;
    std::getline(ifs, eofmarker_buffer);
    if(eofmarker_buffer != "%%EOF") {
        return -1;
    }

    std::streamoff trailer_pos = 0;
    int lf_count = 0;
    while(lf_count < 3) {
        char c;
        trailer_pos--;
        ifs.seekg(trailer_pos, std::ios::end);
        ifs.get(c);
        if(c == 0x0a) {
            lf_count++;
        }
    }

    std::string trailer_buffer;
    std::getline(ifs, trailer_buffer);
    std::stringstream ss(trailer_buffer);
    std::streamoff startxref_pos;
    ss >> startxref_pos;
    return startxref_pos;
}

std::streamoff read_xref(std::ifstream &ifs, std::streamoff startxref_pos, std::map<int, std::streamoff> &cross_reference_table)
{
    ifs.seekg(startxref_pos, std::ios::beg);
    std::streamoff trailer_pos = -1;
    std::string table_header;
    std::getline(ifs, table_header);
    if(table_header != "xref") {
        return -1;
    }
    std::getline(ifs, table_header);
    while(table_header.substr(0, 7) != "trailer") {
        std::stringstream ss(table_header);
        int start_object, number_object;
        ss >> start_object >> number_object;
        for(int i = 0; i < number_object; i++) {
            std::getline(ifs, table_header);
            std::streamoff offset;
            int generation;
            char inuse;
            std::stringstream ss(table_header);
            ss >> offset >> generation >> inuse;
            if(inuse == 'n') {
                cross_reference_table[start_object + i] = offset;
            }
        }
        trailer_pos = ifs.tellg();
        std::getline(ifs, table_header);
    }
    return trailer_pos;
}

std::shared_ptr<object> read_trailer(std::ifstream &ifs, std::streamoff trailer_pos)
{
    ifs.seekg(trailer_pos, std::ios::beg);
    std::string trailer = "";
    std::string trailer_buffer = "";
    std::getline(ifs, trailer_buffer);
    trailer += trailer_buffer.substr(7) + '\n';
    std::getline(ifs, trailer_buffer);        
    while(trailer_buffer != "startxref") {
        trailer += trailer_buffer + '\n';
        std::getline(ifs, trailer_buffer);        
    }
    std::stringstream ss(trailer);
    return parse_object(ss);
}

std::shared_ptr<object> read_body(std::ifstream &ifs, std::streamoff pos)
{
    ifs.seekg(pos, std::ios::beg);
    return parse_object(ifs);
}

std::string hashlib(const char *alg, const std::string message) 
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    std::string md_value(EVP_MAX_MD_SIZE, 0);
    unsigned int md_len, i;
    md = EVP_get_digestbyname(alg);
    mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(mdctx, md, NULL)) {
        printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    if (!EVP_DigestUpdate(mdctx, message.data(), message.size())) {
        printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    if (!EVP_DigestFinal_ex(mdctx, (unsigned char *)md_value.data(), &md_len)) {
        printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    EVP_MD_CTX_free(mdctx);
    return md_value.substr(0, md_len);
}

std::string do_crypt(int do_encrypt, const char *alg, bool padding, const std::string key, const std::string iv, const std::string data, int repeat = 1)
{
    std::string outbuf(data.size() * repeat + EVP_MAX_BLOCK_LENGTH, 0);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, alg, NULL);
    if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL,
                            do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if(!padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }
    if (!EVP_CipherInit_ex2(ctx, NULL, (const unsigned char *)key.data(), (const unsigned char *)iv.data(), do_encrypt, NULL)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    int output_len = 0;
    int outlen;
    for(int i = 0; i < repeat; i++) {
        if (!EVP_CipherUpdate(ctx, (unsigned char *)outbuf.data() + output_len, &outlen, (const unsigned char *)data.data(), data.size())) {
            /* Error */
            EVP_CIPHER_free(cipher);
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        output_len += outlen;
    }
    if (!EVP_CipherFinal_ex(ctx, (unsigned char *)outbuf.data() + output_len, &outlen)) {
        /* Error */
        EVP_CIPHER_free(cipher);
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    output_len += outlen;
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return outbuf.substr(0, output_len);
}

std::string calculate_hash(int R, const std::string password, const std::string salt, const std::string udata)
{
    std::string k = hashlib("SHA256", password + salt + udata);
    if(R < 6) return k;
    int count = 0;
    while(true) {
        count++;
        std::string k1 = password + k + udata;
        std::string e = do_crypt(1, "aes-128-cbc", false, k.substr(0,16), k.substr(16,16), k1, 64);
        int sum = 0;
        for(int i = 0; i < 16; i++) {
            sum += *(unsigned char *)&e.data()[i];
        }
        sum = sum % 3;
        if(sum == 0) {
            k = hashlib("SHA256", e);
        }
        else if(sum == 1) {
            k = hashlib("SHA384", e);
        }
        else {
            k = hashlib("SHA512", e);
        }
        int last_e = *(unsigned char *)&e.back();
        if((count >= 64) && (last_e <= count - 32)) {
            break;
        }
    }
    return k.substr(0,32);
}

std::string verify_owner_password(int R, std::string password, std::string o_value, std::string oe_value, std::string u_value)
{
    password = password.substr(0, 127);
    if(calculate_hash(R, password, o_value.substr(32,8), u_value.substr(0,48)) != o_value.substr(0, 32)) {
        return "";
    }
    std::string iv(16, 0);
    std::string tmp_key = calculate_hash(R, password, o_value.substr(40,8), u_value.substr(0,48));
    std::string key = do_crypt(0, "aes-256-cbc", false, tmp_key, iv, oe_value);
    return key;
}

std::string verify_user_password(int R, std::string password, std::string u_value, std::string ue_value)
{
    password = password.substr(0, 127);
    if(calculate_hash(R, password, u_value.substr(32,8), "") != u_value.substr(0, 32)) {
        return "";
    }
    std::string iv(16, 0);
    std::string tmp_key = calculate_hash(R, password, u_value.substr(40,8), "");
    std::string key = do_crypt(0, "aes-256-cbc", false, tmp_key, iv, ue_value);
    return key;
}

bool verify_perms(std::string key, std::string perms, int p, bool metadata_encrypted)
{
    std::string p2 = do_crypt(0, "aes-256-ecb", false, key, "", perms);
    uint32_t Pvalue = *(uint32_t *)&p;
    std::string p1;
    std::copy((unsigned char *)&Pvalue, (unsigned char *)&Pvalue + 4, std::back_insert_iterator(p1));
    p1.push_back(0xff);
    p1.push_back(0xff);
    p1.push_back(0xff);
    p1.push_back(0xff);
    if(metadata_encrypted) {
        p1.push_back('T');
    }
    else {
        p1.push_back('F');
    }
    p1.push_back('a');
    p1.push_back('d');
    p1.push_back('b');
    return p1== p2.substr(0, 12);
}

std::string verify_v5(std::string password, int R, std::string O, std::string U, std::string OE, std::string UE)
{
    std::string key = verify_owner_password(R, password, O, OE, U);
    if(key == "") {
        key = verify_user_password(R, password, U, UE);
    }
    if(key == "") return "";
    return key;
}

const stream_object* get_stream_object(std::shared_ptr<object> base)
{
    const indirect_object *obj = dynamic_cast<const indirect_object*>(base.get());
    return dynamic_cast<const stream_object*>(obj->get_value().get());
}

const dictionary_object* get_dictonary_object(std::shared_ptr<object> base)
{
    const indirect_object *obj = dynamic_cast<const indirect_object*>(base.get());
    return dynamic_cast<const dictionary_object*>(obj->get_value().get());
}

const array_object* get_array(std::shared_ptr<object> base)
{
    return dynamic_cast<const array_object*>(base.get());
}

const dictionary_object* get_dictonary(std::shared_ptr<object> base)
{
    return dynamic_cast<const dictionary_object*>(base.get());
}

std::string get_string(std::shared_ptr<object> base)
{
    const string_object *s_ptr = dynamic_cast<const string_object*>(base.get());
    return s_ptr->get_value();
}

int get_integer(std::shared_ptr<object> base)
{
    const integer_object *i_ptr = dynamic_cast<const integer_object*>(base.get());
    return i_ptr->get_value();
}

std::string ZlibInflate(const std::string &data)
{
    constexpr auto BUFFER_SIZE = 0x4000;
    auto size = static_cast<unsigned int>(data.size());
    auto outBuf = new unsigned char[BUFFER_SIZE]();
    std::stringstream outStream;
    z_stream zStream{ 0 };
    auto ret = inflateInit(&zStream);

    zStream.avail_in = size;
    zStream.next_in = reinterpret_cast<unsigned char*>(const_cast<char*>(data.data()));
    do
    {
        zStream.next_out = outBuf;
        zStream.avail_out = BUFFER_SIZE;
        ret = inflate(&zStream, Z_NO_FLUSH);
        auto outSize = BUFFER_SIZE - zStream.avail_out;
        outStream.write(reinterpret_cast<char *>(outBuf), outSize);
    } while (zStream.avail_out == 0);

    inflateEnd(&zStream);

    return outStream.str();
}

std::string process_filter(const std::string &filter, const std::string &data)
{
    if(filter == "FlateDecode") {
        return ZlibInflate(data);
    }
    return data;
}

class PDF_reader {
    private:
        std::ifstream ifs;
        std::map<int, std::streamoff> cross_reference_table;
        std::string file_encryption_key;

        std::shared_ptr<object> root_obj;
        std::shared_ptr<object> info_obj;
        std::shared_ptr<object> pages_obj;
        std::vector<std::shared_ptr<object>> page;

        std::shared_ptr<object> follow_reference(const std::shared_ptr<object> base) {
            const indirect_references_object *obj_ptr = dynamic_cast<const indirect_references_object*>(base.get());
            int obj_number = obj_ptr->get_object_number();
            return read_body(ifs, cross_reference_table[obj_number]);
        }

        const dictionary_object* rootobj() {
            return get_dictonary_object(root_obj);
        }
        const dictionary_object* infoobj() {
            return get_dictonary_object(info_obj);
        }
        const dictionary_object* pagesobj() {
            return get_dictonary_object(pages_obj);
        }

        const std::string get_stream(const stream_object* stream_obj)
        {
            auto dict = stream_obj->get_dict();
            std::string filter = "";
            if (dict.isexists("Filter")) {
                filter = get_string(dict["Filter"]);
            }

            auto stream = stream_obj->get_stream();
            if(file_encryption_key.empty()) return process_filter(filter, stream);

            std::string value = do_crypt(0, "aes-256-cbc", true, file_encryption_key, stream.substr(0,16), stream.substr(16));
            return process_filter(filter, value);
        }

        std::string decode_string(const std::string &content) {
            if(file_encryption_key.empty()) return content;

            std::string value = do_crypt(0, "aes-256-cbc", true, file_encryption_key, content.substr(0,16), content.substr(16));
            if(value.size() > 2 && value[0] == -2 && value[1] == -1) {
                std::string le_value;
                for(int i = 0; i < value.size(); i+=2) {
                    le_value += value[i+1];
                    le_value += value[i];
                }
                value = nodec::unicode::utf16to8<std::string>(le_value);
            }
            return value;
        }

    public:
        PDF_reader(std::string filename)
            : ifs(filename, std::ios::binary) 
        {
            if(!ifs) {
                std::cerr << "failed to open file: " << filename << std::endl;
                throw std::runtime_error("file open error");
            }

            int pdf_ver = check_header(ifs);
            if(pdf_ver < 0) {
                std::cerr << "invalid pdf header." << std::endl;
                throw std::runtime_error("header error");
            }

            std::streamoff startxref_pos = get_startxref_pos(ifs);
            if(startxref_pos < 0) {
                std::cerr << "invalid eof marker." << std::endl;
                throw std::runtime_error("footer error");
            }

            std::streamoff trailer_pos = read_xref(ifs, startxref_pos, cross_reference_table);
            if(trailer_pos < 0) {
                std::cerr << "invalid xref." << std::endl;
                throw std::runtime_error("xref error");
            }

            std::shared_ptr<object> trailer = read_trailer(ifs, trailer_pos);
            dictionary_object *trailer_dict = dynamic_cast<dictionary_object*>(trailer.get());
            if(trailer_dict == nullptr) {
                throw std::runtime_error("trailer error");
            }

            int table_size = get_integer((*trailer_dict)["Size"]);
            std::vector<int> ignore_index;
            for(const auto &elem: cross_reference_table) {
                if(elem.first >= table_size) {
                    ignore_index.push_back(elem.first);
                }
            }
            for(const auto &key: ignore_index) {
                cross_reference_table.erase(key);
            }

            if(trailer_dict->isexists("Encrypt")) {
                auto encrypt_obj = follow_reference((*trailer_dict)["Encrypt"]);
                auto encrypt = get_dictonary_object(encrypt_obj);

                auto O = get_string((*encrypt)["O"]);
                auto U = get_string((*encrypt)["U"]);
                auto OE = get_string((*encrypt)["OE"]);
                auto UE = get_string((*encrypt)["UE"]);
                auto Perms = get_string((*encrypt)["Perms"]);
                auto P = get_integer((*encrypt)["P"]);
                auto R = get_integer((*encrypt)["R"]);
                auto V = get_integer((*encrypt)["V"]);
                auto LengthBit = get_integer((*encrypt)["Length"]);

                file_encryption_key = verify_v5("", R, O, U, OE, UE);
                std::cout << "verify: " << verify_perms(file_encryption_key, Perms, P, true) << std::endl;
            }

            root_obj = follow_reference((*trailer_dict)["Root"]);
            info_obj = follow_reference((*trailer_dict)["Info"]);
            pages_obj = follow_reference((*rootobj())["Pages"]);

            auto pagecount = get_integer((*pagesobj())["Count"]);
            std::cout << pagecount << " pages" << std::endl;
            auto pagekids_ptr = get_array((*pagesobj())["Kids"]);
            for(int i = 0; i < pagecount; i++) {
                auto page_obj = follow_reference((*pagekids_ptr)[i]);
                page.push_back(page_obj);
            }
        }

        void print_info() {
            std::cout << "--------Info--------" << std::endl;
            auto keys = infoobj()->get_keys();
            for(const auto &key: keys) {
                std::cout << key << " : ";
                auto str = get_string((*infoobj())[key]);
                std::cout << decode_string(str) << std::endl;
            }
        }

        void extract_pages(int page_count = 0) {
            for(const auto &p: page) {
                page_count++;
                std::cout << "page: " << page_count << std::endl;
                auto dict = get_dictonary_object(p);
                if(dict->isexists("Resources")) {
                    auto resources = get_dictonary((*dict)["Resources"]);
                    if(resources->isexists("XObject")) {
                        auto xobject = get_dictonary((*resources)["XObject"]);
                        if(xobject->isexists("Im0")) {
                            auto Im0 = follow_reference((*xobject)["Im0"]);
                            auto image_stream = get_stream_object(Im0);
                            std::stringstream ss;
                            ss << "page" << std::setfill('0') << std::setw(4) << page_count;
                            std::ofstream ofs(ss.str()+".jpg", std::ios::binary);
                            ofs << get_stream(image_stream);
                        }
                    }
                }
            }
        }
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "usage: " << argv[0] << " input.pdf (start_page_no)" << std::endl;
        return 0;
    }
    auto pdf = PDF_reader(argv[1]);
    int start_page = 0;
    if (argc >= 3) {
        std::stringstream(argv[2]) >> start_page; 
    }

    pdf.print_info();
    pdf.extract_pages(start_page);

    return 0;
}