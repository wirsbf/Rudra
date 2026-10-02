# 函数清单:type.cc + typeop.cc + cast.cc + printc.cc + prettyprint.cc + printlanguage.cc

来源:Ghidra 6 个类型/输出 .cc(~620 函数)
Rudra 对应:`src/type_system/` + `src/typeop.rs` + `src/printc.rs` + `src/prettyprint.rs` + `src/printlanguage.rs`

## type.cc(~175 函数)

Datatype 基类 + TypeChar/Unicode/Void/Pointer/Array/Enum/Struct/Union/PartialEnum/PartialStruct/PartialUnion/PointerRel/Code/Spacebase + TypeFactory。

| 行段 | 函数 | 状态 |
|---|---|---|
| L126-L749 | Datatype 基类(hasSameVariableBase/printRaw/findTruncation/getSubType/nearestArrayedComponent*/compare/compareDependency/encode/encodeBasic/encodeRef/isPrimitiveWhole/encodeTypedef/calcAlignSize/isPtrsubMatching/getStripped/resolveInFlow/findResolve/findCompatibleResolve/resolveTruncation/decodeBasic/hashName/hashSize/encodeIntegerFormat/decodeIntegerFormat) | 🔍 |
| L768-L832 | TypeField(TypeField/encode) + TypeChar(decode/encode) | 🔍 |
| L837-L1204 | TypeUnicode(setflags/decode/ctor/encode) + TypeVoid + TypePointer(printRaw/getSubType/compare/compareDependency/encode/testForArraySlack/decode/calcSubmeta/calcTruncate/downChain/isPtrsubMatching/resolveInFlow/findResolve) | 🔍 |
| L1204-L1322 | TypeArray(printRaw/compare/compareDependency/getSubType/getHoleSize/getSubEntry/encode/resolveInFlow/findResolve/findCompatibleResolve/decode) | 🔍 |
| L1346-L1597 | TypeEnum(hasNamedValue/getMatches/compare/compareDependency/encode/decode/assignValues) | 🔍 |
| L1551-L1970 | TypeStruct(setFields/getFieldIter/getLowerBoundField/findTruncation/getSubType/getHoleSize/nearestArrayedComponent*/compare/compareDependency/encode/decodeFields/scoreSingleComponent/resolveInFlow/findResolve/findCompatibleResolve/assignFieldOffsets) | 🔍 |
| L2002-L2247 | TypeUnion(setFields/decodeFields/ctor/compare/compareDependency/encode/resolveInFlow/findResolve/resolveTruncation/findTruncation/findCompatibleResolve/assignFieldOffsets) | 🔍 |
| L2247-L2552 | TypePartialEnum/PartialStruct/PartialUnion(各 ctor/printRaw/getSub*/compare/encode/resolve*) | 🔍 |
| L2552-L2713 | TypePointerRel(decode/evaluateThruParent/printRaw/compare/encode/downChain/isPtrsubMatching/getPtrToFromParent) | 🔍 |
| L2713-L2935 | TypeCode(setPrototype×2/ctor/dtor/printRaw/compareBasic/getSubType/compare/compareDependency/encode/decodeStub/decodePrototype) | 🔍 |
| L2935-L3106 | TypeSpacebase(getMap/getSubType/nearestArrayedComponent*/compare/compareDependency/getAddress/encode/decode) | 🔍 |
| L3106-L4665 | TypeFactory(clearCache/setupSizes/setCoreType/cacheCoreTypes/clear/clearNoncore/dtor/getAlignment/getPrimitiveAlignSize/findByIdLocal/findById/findByName/findNoName/insert/findAdd/setName/setDisplayFormat/setFields(Struct/Union)/setPrototype/setEnumValues/orderRecurse/dependentOrder/getTypeVoid/Char/Unicode/Base/BaseNoChar/Char/Code/Code(name)/recalcPointerSubmeta/insertWarning/removeWarning/resolveIncompleteTypedefs/getTypedef/getTypePointerStripArray/getTypePointer×3/getTypeArray/getTypeStruct/getTypePartialStruct/getTypeUnion/getTypePartialUnion/getTypeEnum/getTypePartialEnum/getTypeSpacebase/getTypeCode(proto)/getTypePointerRel×2/getTypePointerWithSpace/resizePointer/getExactPiece/destroyType/concretize/decodeType/decodeTypeWithCodeFlags/encode/encodeCoreTypes/decodeTypedef/decodeEnum/decodeStruct/decodeUnion/decodeCode/decodeTypeNoRef/decode/decodeCoreTypes/decodeDataOrganization/decodeAlignmentMap/setDefaultAlignmentMap/parseEnumConfig) | 🔍 |

**type.cc 统计**:~175 函数。全部 🔍。

## typeop.cc(~155 函数)

TypeOp 基类 + 每个 OpCode 的 TypeOp 子类(copy/load/store/branch/cbranch/branchind/call/callind/callother/return/equal/notequal/intsless*/intless*/intzext/intsext/intadd/sub/carry*/scarry/sborrow/2comp/negate/xor/and/or/left/right/sright/mult/div/sdiv/rem/srem/boolnegate/xor/and/or/float*/multi/indirect/piece/subpiece/cast/ptradd/ptrsub/segment/cpoolref/new/insert/extract/popcount/lzcount)。

| 行段 | 函数 | 状态 |
|---|---|---|
| L24-L322 | TypeOp 基类(registerInstructions/selectJavaOperators/floatSignManipulation/propagateToPointer/propagateFromPointer/ctor/dtor/isCommutative/getOutputLocal/getInputLocal/getOutputToken/getInputCast/propagateType) + TypeOpBinary/Unary/Func | 🔍 |
| L390-L4500 | 各 TypeOp 子类的 ctor/printRaw/getInputCast/getOutputToken/propagateType/getInputLocal/getOutputLocal/getOperatorName/absorbZext/preferredZextSize/computeByteOffsetForComposite 等 | 🔍 |

**typeop.cc 统计**:~155 函数。全部 🔍。

## cast.cc(17 函数)

CastStrategy 基类 + CastStrategyC + CastStrategyJava。

| 行 | 函数 | 状态 |
|---|---|---|
| L23/L38/L79 | CastStrategy::setTypeFactory/markExplicitUnsigned/markExplicitLongSize | 🔍 |
| L107-L471 | CastStrategyC(checkIntPromotionForCompare/Extension/localExtensionType/intPromotionType/isExtensionCastImplied/castStandard/arithmeticOutputStandard/isSubpieceCast×2/isSextCast/isZextCast) | 🔍 |
| L471-L533 | CastStrategyJava(castStandard/isZextCast) | 🔍 |

**cast.cc 统计**:17 函数。全部 🔍。

## printc.cc(~104 函数)

PrintCCapability + PrintC。

| 行段 | 函数 | 状态 |
|---|---|---|
| L108-L143 | PrintCCapability + PrintC ctor | 🔍 |
| L143-L353 | buildTypeStack/pushPrototypeInputs/pushSymbolScope/emitSymbolScope/pushTypeStart/End/checkArrayDeref/checkAddressOfCast | 🔍 |
| L424-L929 | op 系列(opFunc/TypeCast/HiddenFunc/Copy/Load/Store/Branch/Cbranch/Branchind/Call/Callind/Callother/Constructor/Return/IntZext/IntSext/BoolNegate/FloatInt2Float/Subpiece/Ptradd/Ptrsub) | 🔍 |
| L1150-L1288 | opSegmentOp/CpoolRefOp/NewOp/InsertOp/ExtractOp | 🔍 |
| L1288-L1534 | push_integer/push_float/printUnicode/pushType/pushBoolConstant/doEmitWideCharPrefix/printCharHexEscape/printCharacterConstant/getHiddenThisSlot/resetDefaultsPrintC | 🔍 |
| L1534-L2085 | pushCharConstant/pushEnumConstant/pushPtrCharConstant/pushPtrCodeConstant/pushConstant/pushEquate/pushAnnotation/pushSymbol/pushUnnamedLocation/pushPartialSymbol/pushMismatchSymbol/pushImpliedField | 🔍 |
| L2120-L2194 | emitStructDefinition/emitEnumDefinition | 🔍 |
| L2194-L2332 | emitPrototypeOutput/Inputs/emitLocalVarDecls/emitStatement/emitGotoStatement/resetDefaults/initializeFromArchitecture/adjustTypeOperators/setCommentStyle | 🔍 |
| L2369-L2678 | emitTypeDefinition/checkPrintNegation/docTypeDefinitions/emitInplaceOp/emitExpression/emitVarDecl(Statement)/emitScopeVarDecls/emitFunctionDeclaration/emitGlobalVarDeclsRecursive/docAllGlobals/docSingleGlobal/docFunction | 🔍 |
| L2678-L3359 | emitBlockBasic/Graph/Copy/Goto/Ls/Condition/If/WhileDo(ForLoop)/DoWhile/InfLoop/Switch(emitSwitchCase/emitLabel/LabelStatement/AnyLabelStatement) | 🔍 |
| L3231-L3373 | emitCommentGroup/BlockTreeTree/FuncHeader + genericFunctionName/genericTypeName | 🔍 |

**printc.cc 统计**:~104 函数。全部 🔍。

## prettyprint.cc(~92 函数)

Emit 基类 + EmitMarkup + TokenSplit + EmitPrettyPrint。

| 行段 | 函数 | 状态 |
|---|---|---|
| L46-L93 | Emit::spaces/openBraceIndent/openBrace | 🔍 |
| L93-L323 | EmitMarkup(全部 begin/end/tag*/print/openParen/closeParen/setOutputStream/setPackedOutput) | 🔍 |
| L349-L541 | TokenSplit(print/printDebug) | 🔍 |
| L541-L1237 | EmitPrettyPrint(全部 expand/overflow/print/advanceleft/scan/check*/begin/end/tag*/print/openParen/closeParen/spaces/startIndent/stopIndent/flush/setMarkup/setMaxLineSize/resetDefaults) | 🔍 |

**prettyprint.cc 统计**:~92 函数。全部 🔍。

## printlanguage.cc(~30 函数)

PrintLanguageCapability + PrintLanguage。

| 行 | 函数 | 状态 |
|---|---|---|
| L30-L62 | PrintLanguageCapability(getDefault/initialize/findCapability) | 🔍 |
| L62-L793 | PrintLanguage(ctor/dtor/setLineCommentIndent/setCommentDelimeter/popScope/pushOp/pushAtom/pushVn/pushVnExplicit/pushSymbolDetail/parentheses/emitOp/emitAtom/unicodeNeedsEscape/escapeCharacterData/recurse/opBinary/opUnary/resetDefaultsInternal/emitLineComment/setPackedOutput/setFlat/resetDefaults/clear/setIntegerFormat/unnamedField/mostNaturalBase/formatBinary) | 🔍 |

**printlanguage.cc 统计**:~30 函数。全部 🔍。

**六文件合计**:~573 函数。
