// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: idx.proto

#include "idx.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)
class File_EntryDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<File_Entry>
      _instance;
} _File_Entry_default_instance_;
class IdxListDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<IdxList>
      _instance;
} _IdxList_default_instance_;
namespace protobuf_idx_2eproto {
void InitDefaultsFile_EntryImpl() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
  ::google::protobuf::internal::InitProtobufDefaultsForceUnique();
#else
  ::google::protobuf::internal::InitProtobufDefaults();
#endif  // GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
  {
    void* ptr = &::_File_Entry_default_instance_;
    new (ptr) ::File_Entry();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::File_Entry::InitAsDefaultInstance();
}

void InitDefaultsFile_Entry() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &InitDefaultsFile_EntryImpl);
}

void InitDefaultsIdxListImpl() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
  ::google::protobuf::internal::InitProtobufDefaultsForceUnique();
#else
  ::google::protobuf::internal::InitProtobufDefaults();
#endif  // GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
  protobuf_idx_2eproto::InitDefaultsFile_Entry();
  {
    void* ptr = &::_IdxList_default_instance_;
    new (ptr) ::IdxList();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::IdxList::InitAsDefaultInstance();
}

void InitDefaultsIdxList() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &InitDefaultsIdxListImpl);
}

::google::protobuf::Metadata file_level_metadata[2];

const ::google::protobuf::uint32 TableStruct::offsets[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::File_Entry, _has_bits_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::File_Entry, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::File_Entry, idx_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::File_Entry, name_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::File_Entry, recovery_),
  2,
  0,
  1,
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::IdxList, _has_bits_),
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::IdxList, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::IdxList, file_entry_),
  ~0u,
};
static const ::google::protobuf::internal::MigrationSchema schemas[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { 0, 8, sizeof(::File_Entry)},
  { 11, 17, sizeof(::IdxList)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&::_File_Entry_default_instance_),
  reinterpret_cast<const ::google::protobuf::Message*>(&::_IdxList_default_instance_),
};

void protobuf_AssignDescriptors() {
  AddDescriptors();
  ::google::protobuf::MessageFactory* factory = NULL;
  AssignDescriptors(
      "idx.proto", schemas, file_default_instances, TableStruct::offsets, factory,
      file_level_metadata, NULL, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_PROTOBUF_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 2);
}

void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\tidx.proto\"9\n\nFile_Entry\022\013\n\003idx\030\001 \002(\005\022\014"
      "\n\004name\030\002 \002(\t\022\020\n\010recovery\030\003 \002(\014\"*\n\007IdxLis"
      "t\022\037\n\nfile_entry\030\001 \003(\0132\013.File_Entry"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 114);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "idx.proto", &protobuf_RegisterTypes);
}

void AddDescriptors() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;
}  // namespace protobuf_idx_2eproto

// ===================================================================

void File_Entry::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int File_Entry::kIdxFieldNumber;
const int File_Entry::kNameFieldNumber;
const int File_Entry::kRecoveryFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

File_Entry::File_Entry()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    ::protobuf_idx_2eproto::InitDefaultsFile_Entry();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:File_Entry)
}
File_Entry::File_Entry(const File_Entry& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _has_bits_(from._has_bits_),
      _cached_size_(0) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  name_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.has_name()) {
    name_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.name_);
  }
  recovery_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.has_recovery()) {
    recovery_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.recovery_);
  }
  idx_ = from.idx_;
  // @@protoc_insertion_point(copy_constructor:File_Entry)
}

void File_Entry::SharedCtor() {
  _cached_size_ = 0;
  name_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  recovery_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  idx_ = 0;
}

File_Entry::~File_Entry() {
  // @@protoc_insertion_point(destructor:File_Entry)
  SharedDtor();
}

void File_Entry::SharedDtor() {
  name_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  recovery_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void File_Entry::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* File_Entry::descriptor() {
  ::protobuf_idx_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_idx_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const File_Entry& File_Entry::default_instance() {
  ::protobuf_idx_2eproto::InitDefaultsFile_Entry();
  return *internal_default_instance();
}

File_Entry* File_Entry::New(::google::protobuf::Arena* arena) const {
  File_Entry* n = new File_Entry;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void File_Entry::Clear() {
// @@protoc_insertion_point(message_clear_start:File_Entry)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  if (cached_has_bits & 3u) {
    if (cached_has_bits & 0x00000001u) {
      GOOGLE_DCHECK(!name_.IsDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited()));
      (*name_.UnsafeRawStringPointer())->clear();
    }
    if (cached_has_bits & 0x00000002u) {
      GOOGLE_DCHECK(!recovery_.IsDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited()));
      (*recovery_.UnsafeRawStringPointer())->clear();
    }
  }
  idx_ = 0;
  _has_bits_.Clear();
  _internal_metadata_.Clear();
}

bool File_Entry::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:File_Entry)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required int32 idx = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(8u /* 8 & 0xFF */)) {
          set_has_idx();
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int32, ::google::protobuf::internal::WireFormatLite::TYPE_INT32>(
                 input, &idx_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // required string name = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(18u /* 18 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_name()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
            this->name().data(), static_cast<int>(this->name().length()),
            ::google::protobuf::internal::WireFormat::PARSE,
            "File_Entry.name");
        } else {
          goto handle_unusual;
        }
        break;
      }

      // required bytes recovery = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(26u /* 26 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadBytes(
                input, this->mutable_recovery()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:File_Entry)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:File_Entry)
  return false;
#undef DO_
}

void File_Entry::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:File_Entry)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // required int32 idx = 1;
  if (cached_has_bits & 0x00000004u) {
    ::google::protobuf::internal::WireFormatLite::WriteInt32(1, this->idx(), output);
  }

  // required string name = 2;
  if (cached_has_bits & 0x00000001u) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->name().data(), static_cast<int>(this->name().length()),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "File_Entry.name");
    ::google::protobuf::internal::WireFormatLite::WriteStringMaybeAliased(
      2, this->name(), output);
  }

  // required bytes recovery = 3;
  if (cached_has_bits & 0x00000002u) {
    ::google::protobuf::internal::WireFormatLite::WriteBytesMaybeAliased(
      3, this->recovery(), output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        _internal_metadata_.unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:File_Entry)
}

::google::protobuf::uint8* File_Entry::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:File_Entry)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = _has_bits_[0];
  // required int32 idx = 1;
  if (cached_has_bits & 0x00000004u) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt32ToArray(1, this->idx(), target);
  }

  // required string name = 2;
  if (cached_has_bits & 0x00000001u) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8StringNamedField(
      this->name().data(), static_cast<int>(this->name().length()),
      ::google::protobuf::internal::WireFormat::SERIALIZE,
      "File_Entry.name");
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        2, this->name(), target);
  }

  // required bytes recovery = 3;
  if (cached_has_bits & 0x00000002u) {
    target =
      ::google::protobuf::internal::WireFormatLite::WriteBytesToArray(
        3, this->recovery(), target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:File_Entry)
  return target;
}

size_t File_Entry::RequiredFieldsByteSizeFallback() const {
// @@protoc_insertion_point(required_fields_byte_size_fallback_start:File_Entry)
  size_t total_size = 0;

  if (has_name()) {
    // required string name = 2;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->name());
  }

  if (has_recovery()) {
    // required bytes recovery = 3;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::BytesSize(
        this->recovery());
  }

  if (has_idx()) {
    // required int32 idx = 1;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->idx());
  }

  return total_size;
}
size_t File_Entry::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:File_Entry)
  size_t total_size = 0;

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        _internal_metadata_.unknown_fields());
  }
  if (((_has_bits_[0] & 0x00000007) ^ 0x00000007) == 0) {  // All required fields are present.
    // required string name = 2;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::StringSize(
        this->name());

    // required bytes recovery = 3;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::BytesSize(
        this->recovery());

    // required int32 idx = 1;
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::Int32Size(
        this->idx());

  } else {
    total_size += RequiredFieldsByteSizeFallback();
  }
  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void File_Entry::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:File_Entry)
  GOOGLE_DCHECK_NE(&from, this);
  const File_Entry* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const File_Entry>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:File_Entry)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:File_Entry)
    MergeFrom(*source);
  }
}

void File_Entry::MergeFrom(const File_Entry& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:File_Entry)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  cached_has_bits = from._has_bits_[0];
  if (cached_has_bits & 7u) {
    if (cached_has_bits & 0x00000001u) {
      set_has_name();
      name_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.name_);
    }
    if (cached_has_bits & 0x00000002u) {
      set_has_recovery();
      recovery_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.recovery_);
    }
    if (cached_has_bits & 0x00000004u) {
      idx_ = from.idx_;
    }
    _has_bits_[0] |= cached_has_bits;
  }
}

void File_Entry::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:File_Entry)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void File_Entry::CopyFrom(const File_Entry& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:File_Entry)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool File_Entry::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000007) != 0x00000007) return false;
  return true;
}

void File_Entry::Swap(File_Entry* other) {
  if (other == this) return;
  InternalSwap(other);
}
void File_Entry::InternalSwap(File_Entry* other) {
  using std::swap;
  name_.Swap(&other->name_);
  recovery_.Swap(&other->recovery_);
  swap(idx_, other->idx_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  _internal_metadata_.Swap(&other->_internal_metadata_);
  swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata File_Entry::GetMetadata() const {
  protobuf_idx_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_idx_2eproto::file_level_metadata[kIndexInFileMessages];
}


// ===================================================================

void IdxList::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int IdxList::kFileEntryFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

IdxList::IdxList()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  if (GOOGLE_PREDICT_TRUE(this != internal_default_instance())) {
    ::protobuf_idx_2eproto::InitDefaultsIdxList();
  }
  SharedCtor();
  // @@protoc_insertion_point(constructor:IdxList)
}
IdxList::IdxList(const IdxList& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL),
      _has_bits_(from._has_bits_),
      _cached_size_(0),
      file_entry_(from.file_entry_) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:IdxList)
}

void IdxList::SharedCtor() {
  _cached_size_ = 0;
}

IdxList::~IdxList() {
  // @@protoc_insertion_point(destructor:IdxList)
  SharedDtor();
}

void IdxList::SharedDtor() {
}

void IdxList::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* IdxList::descriptor() {
  ::protobuf_idx_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_idx_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const IdxList& IdxList::default_instance() {
  ::protobuf_idx_2eproto::InitDefaultsIdxList();
  return *internal_default_instance();
}

IdxList* IdxList::New(::google::protobuf::Arena* arena) const {
  IdxList* n = new IdxList;
  if (arena != NULL) {
    arena->Own(n);
  }
  return n;
}

void IdxList::Clear() {
// @@protoc_insertion_point(message_clear_start:IdxList)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  file_entry_.Clear();
  _has_bits_.Clear();
  _internal_metadata_.Clear();
}

bool IdxList::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:IdxList)
  for (;;) {
    ::std::pair< ::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .File_Entry file_entry = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(10u /* 10 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessage(input, add_file_entry()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:IdxList)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:IdxList)
  return false;
#undef DO_
}

void IdxList::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:IdxList)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .File_Entry file_entry = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->file_entry_size()); i < n; i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessageMaybeToArray(
      1, this->file_entry(static_cast<int>(i)), output);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        _internal_metadata_.unknown_fields(), output);
  }
  // @@protoc_insertion_point(serialize_end:IdxList)
}

::google::protobuf::uint8* IdxList::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:IdxList)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .File_Entry file_entry = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->file_entry_size()); i < n; i++) {
    target = ::google::protobuf::internal::WireFormatLite::
      InternalWriteMessageToArray(
        1, this->file_entry(static_cast<int>(i)), deterministic, target);
  }

  if (_internal_metadata_.have_unknown_fields()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields(), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:IdxList)
  return target;
}

size_t IdxList::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:IdxList)
  size_t total_size = 0;

  if (_internal_metadata_.have_unknown_fields()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        _internal_metadata_.unknown_fields());
  }
  // repeated .File_Entry file_entry = 1;
  {
    unsigned int count = static_cast<unsigned int>(this->file_entry_size());
    total_size += 1UL * count;
    for (unsigned int i = 0; i < count; i++) {
      total_size +=
        ::google::protobuf::internal::WireFormatLite::MessageSize(
          this->file_entry(static_cast<int>(i)));
    }
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = cached_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void IdxList::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:IdxList)
  GOOGLE_DCHECK_NE(&from, this);
  const IdxList* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const IdxList>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:IdxList)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:IdxList)
    MergeFrom(*source);
  }
}

void IdxList::MergeFrom(const IdxList& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:IdxList)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  file_entry_.MergeFrom(from.file_entry_);
}

void IdxList::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:IdxList)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void IdxList::CopyFrom(const IdxList& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:IdxList)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool IdxList::IsInitialized() const {
  if (!::google::protobuf::internal::AllAreInitialized(this->file_entry())) return false;
  return true;
}

void IdxList::Swap(IdxList* other) {
  if (other == this) return;
  InternalSwap(other);
}
void IdxList::InternalSwap(IdxList* other) {
  using std::swap;
  file_entry_.InternalSwap(&other->file_entry_);
  swap(_has_bits_[0], other->_has_bits_[0]);
  _internal_metadata_.Swap(&other->_internal_metadata_);
  swap(_cached_size_, other->_cached_size_);
}

::google::protobuf::Metadata IdxList::GetMetadata() const {
  protobuf_idx_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_idx_2eproto::file_level_metadata[kIndexInFileMessages];
}


// @@protoc_insertion_point(namespace_scope)

// @@protoc_insertion_point(global_scope)
