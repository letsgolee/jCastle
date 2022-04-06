/**
 * A Javascript implemenation of OID - Object ID
 * 
 * @author Jacob Lee
 *
 * Copyright (C) 2015-2022 Jacob Lee.
 */



var jCastle = require('./jCastle');
require('./oid');

jCastle.oid.extra.kr =
{
	"1.2.410.200004.2.1": { name: "공인인증기관 일반인증서", comment: "공인인증기관 일반인증서", obsolete: false },

	"1.2.410.200005.1.1.1": { name: "금융결제원 금융개인", comment: "금융결제원(Yessign) 금융개인", obsolete: false },
	"1.2.410.200005.1.1.2": { name: "금융결제원 금융기업", comment: "금융결제원(Yessign) 금융기업", obsolete: false },
	"1.2.410.200005.1.1.4": { name: "금융결제원 은행개인", comment: "금융결제원(Yessign) 은행개인", obsolete: false },
	"1.2.410.200005.1.1.5": { name: "금융결제원 범용기업", comment: "금융결제원(Yessign) 범용기업", obsolete: false },

	"1.2.410.200004.5.1.1.1": { name: "한국증권전산 스페셜개인", comment: "한국증권전산(SignKorea) 스페셜개인", obsolete: false },
	"1.2.410.200004.5.1.1.2": { name: "한국증권전산 스페셜개인서버", comment: "한국증권전산(SignKorea) 스페셜개인서버", obsolete: false },
	"1.2.410.200004.5.1.1.3": { name: "한국증권전산 스페셜법인", comment: "한국증권전산(SignKorea) 스페셜법인", obsolete: false },
	"1.2.410.200004.5.1.1.4": { name: "한국증권전산 스페셜서버", comment: "한국증권전산(SignKorea) 스페셜서버", obsolete: false },
	"1.2.410.200004.5.1.1.5": { name: "한국증권전산 범용개인", comment: "한국증권전산(SignKorea) 범용개인", obsolete: false },
	"1.2.410.200004.5.1.1.6": { name: "한국증권전산 범용개인서버", comment: "한국증권전산(SignKorea) 범용개인서버", obsolete: false },
	"1.2.410.200004.5.1.1.7": { name: "한국증권전산 범용법인", comment: "한국증권전산(SignKorea) 범용법인", obsolete: false },
	"1.2.410.200004.5.1.1.8": { name: "한국증권전산 범용서버", comment: "한국증권전산(SignKorea) 범용서버", obsolete: false },
	"1.2.410.200004.5.1.1.9": { name: "한국증권전산 골드개인", comment: "한국증권전산(SignKorea) 골드개인", obsolete: false },
	"1.2.410.200004.5.1.1.10": { name: "한국증권전산 골드개인서버", comment: "한국증권전산(SignKorea) 골드개인서버", obsolete: false },
	"1.2.410.200004.5.1.1.11": { name: "한국증권전산 실버개인", comment: "한국증권전산(SignKorea) 실버개인", obsolete: false },
	"1.2.410.200004.5.1.1.12": { name: "한국증권전산 실버법인", comment: "한국증권전산(SignKorea) 실버법인", obsolete: false },

	"1.2.410.200012.1.1.1": { name: "한국무역정보통신 전자거래서명용(개인)", comment: "한국무역정보통신(TradeSign) 전자거래서명용(개인)", obsolete: false },
	"1.2.410.200012.1.1.2": { name: "한국무역정보통신 전자거래암호용(개인)", comment: "한국무역정보통신(TradeSign) 전자거래암호용(개인)", obsolete: false },
	"1.2.410.200012.1.1.3": { name: "한국무역정보통신 전자거래서명용(법인)", comment: "한국무역정보통신(TradeSign) 전자거래서명용(법인)", obsolete: false },
	"1.2.410.200012.1.1.4": { name: "한국무역정보통신 전자거래암호용(법인)", comment: "한국무역정보통신(TradeSign) 전자거래암호용(법인)", obsolete: false },
	"1.2.410.200012.1.1.5": { name: "한국무역정보통신 전자거래서명용(서버)", comment: "한국무역정보통신(TradeSign) 전자거래서명용(서버)", obsolete: false },
	"1.2.410.200012.1.1.6": { name: "한국무역정보통신 전자거래암호용(서버)", comment: "한국무역정보통신(TradeSign) 전자거래암호용(서버)", obsolete: false },
	"1.2.410.200012.1.1.7": { name: "한국무역정보통신 전자무역서명용(개인)", comment: "한국무역정보통신(TradeSign) 전자무역서명용(개인)", obsolete: false },
	"1.2.410.200012.1.1.8": { name: "한국무역정보통신 전자무역암호용(개인)", comment: "한국무역정보통신(TradeSign) 전자무역암호용(개인)", obsolete: false },
	"1.2.410.200012.1.1.9": { name: "한국무역정보통신 전자무역서명용(법인)", comment: "한국무역정보통신(TradeSign) 전자무역서명용(법인)", obsolete: false },
	"1.2.410.200012.1.1.10": { name: "한국무역정보통신 전자무역암호용(법인)", comment: "한국무역정보통신(TradeSign) 전자무역암호용(법인)", obsolete: false },
	"1.2.410.200012.1.1.11": { name: "한국무역정보통신 전자무역서명용(서버)", comment: "한국무역정보통신(TradeSign) 전자무역서명용(서버)", obsolete: false },
	"1.2.410.200012.1.1.12": { name: "한국무역정보통신 전자무역암호용(서버)", comment: "한국무역정보통신(TradeSign) 전자무역암호용(서버)", obsolete: false },

	"1.2.410.200004.5.4.1.1": { name: "한국전자인증 범용(개인)", comment: "한국전자인증(CrossCert) 범용(개인)", obsolete: false },
	"1.2.410.200004.5.4.1.2": { name: "한국전자인증 범용(법인)", comment: "한국전자인증(CrossCert) 범용(법인)", obsolete: false },
	"1.2.410.200004.5.4.1.3": { name: "한국전자인증 범용(서버)", comment: "한국전자인증(CrossCert) 범용(서버)", obsolete: false },
	"1.2.410.200004.5.4.1.4": { name: "한국전자인증 특수목적용(개인)", comment: "한국전자인증(CrossCert) 특수목적용(개인)", obsolete: false },
	"1.2.410.200004.5.4.1.5": { name: "한국전자인증 특수목적용(법인)", comment: "한국전자인증(CrossCert) 특수목적용(법인)", obsolete: false },

	"1.2.410.200004.5.2.1.1": { name: "한국정보인증 1등급인증서(법인)", comment: "한국정보인증(SignGate) 1등급인증서(법인)", obsolete: false },
	"1.2.410.200004.5.2.1.2": { name: "한국정보인증 범용개인", comment: "한국정보인증(SignGate) 범용개인", obsolete: false },
	"1.2.410.200004.5.2.1.3": { name: "한국정보인증 특별등급(전자입찰)", comment: "한국정보인증(SignGate) 특별등급(전자입찰)", obsolete: false },
	"1.2.410.200004.5.2.1.4": { name: "한국정보인증 1등급인증서(서버)", comment: "한국정보인증(SignGate) 1등급인증서(서버)", obsolete: false },
	"1.2.410.200004.5.2.1.5": { name: "한국정보인증 특별등급법인", comment: "한국정보인증(SignGate) 특별등급법인", obsolete: false },

	"1.2.410.200004.5.3.1.1": { name: "한국전산원 1등급(기관/단체)", comment: "한국전산원(NCA) 1등급(기관/단체)", obsolete: false },
	"1.2.410.200004.5.3.1.2": { name: "한국전산원 1등급(법인)", comment: "한국전산원(NCA) 1등급(법인)", obsolete: false },
	"1.2.410.200004.5.3.1.3": { name: "한국전산원 1등급(서버)", comment: "한국전산원(NCA) 1등급(서버)", obsolete: false },
	"1.2.410.200004.5.3.1.9": { name: "한국전산원 1등급(개인)", comment: "한국전산원(NCA) 1등급(개인)", obsolete: false },
	"1.2.410.200004.5.3.1.5": { name: "한국전산원 특수목적용(기관/단체)", comment: "한국전산원(NCA) 특수목적용(기관/단체)", obsolete: false },
	"1.2.410.200004.5.3.1.6": { name: "한국전산원 특수목적용(법인)", comment: "한국전산원(NCA) 특수목적용(법인)", obsolete: false },
	"1.2.410.200004.5.3.1.7": { name: "한국전산원 특수목적용(서버)", comment: "한국전산원(NCA) 특수목적용(서버)", obsolete: false },
	"1.2.410.200004.5.3.1.8": { name: "한국전산원 특수목적용(개인)", comment: "한국전산원(NCA) 특수목적용(개인)", obsolete: false },

	"1.2.392.200132": { name: "일본상공회의소", comment: "JCCI 일본상공회의소", obsolete: false },
	"1.2.392.200132.1": { name: "일본상공회의소 비지니스인증서비스(BCA 접속)", comment: "JCCI 일본 상공회의소 비지니스 인증 서비스(BCA 접속)", obsolete: false },
	"1.2.392.200132.1.1": { name: "일본상공회의소 비지니스인증서비스 타입1 업무policy 및 운용규정", comment: "JCCI 비지니스 인증 서비스 타입 1 업무 policy 및 운용 규정", obsolete: false },
	"1.2.392.200132.1.1": { name: "일본상공회의소 비지니스인증서비스 타입1 증명서발행policy", comment: "JCCI 비지니스 인증 서비스 타입 1 증명서 발행 policy", obsolete: false },
	//"2.5.29.32.0": { name: "일본상공회의소 any-policy", comment: "JCCI 일본상공회의소 any-policy", obsolete: false },

	"1.2.410.100001.2.1.1": { name: "행정안전부 전자관인", comment: "행정안전부 전자관인", obsolete: false },
	"1.2.410.100001.2.1.2": { name: "행정안전부 컴퓨터용", comment: "행정안전부 컴퓨터용", obsolete: false },
	"1.2.410.100001.2.1.3": { name: "행정안전부 전자특수관인", comment: "행정안전부 전자특수관인", obsolete: false },
	"1.2.410.100001.2.1.4": { name: "공공/민간 전자관인", comment: "행정안전부 공공/민간 전자관인", obsolete: false },
	"1.2.410.100001.2.1.5": { name: "공공/민간 컴퓨터용", comment: "행정안전부 공공/민간 컴퓨터용", obsolete: false },
	"1.2.410.100001.2.1.6": { name: "공공/민간 특수목적용", comment: "행정안전부 공공/민간 특수목적용", obsolete: false },
	"1.2.410.100001.2.2.1": { name: "행정안전부 일반인증서", comment: "행정안전부 일반인증서", obsolete: false },
	"1.2.410.100001.2.2.2": { name: "공공/민간 개인용인증서", comment: "행정안전부 공공/민간 개인용인증서", obsolete: false },
	"1.2.410.100001.5.3.1.3": { name: "교육과학기술부 일반인증서", comment: "교육과학기술부 일반인증서", obsolete: false }
};

// for (var oid in jCastle.oid.extra.kr) {
// 	//if (jCastle.oid.extra.kr.hasOwnProperty(oid)) {
// 		jCastle.oid.data[oid] = jCastle.oid.extra.kr[oid];
// 	//}
// }

Object.assign(jCastle.oid.data, jCastle.oid.extra.kr);

module.exports = jCastle.oid.extra.kr;