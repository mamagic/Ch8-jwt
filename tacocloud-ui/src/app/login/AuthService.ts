import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private readonly TOKEN_KEY = 'jwt-token';
  private loggedIn = false;

  login() {
    // 로그인 처리
    this.loggedIn = true;
  }

  logout() {
    // 로그아웃 처리
    this.loggedIn = false;
  }

  // 토큰 저장
    storeToken(token: string): void {
      localStorage.setItem(this.TOKEN_KEY, token);
    }

    // 토큰 가져오기
    getToken(): string | null {
      return localStorage.getItem(this.TOKEN_KEY);
    }

    // 토큰 삭제
    removeToken(): void {
      localStorage.removeItem(this.TOKEN_KEY);
    }

    // 사용자 로그인 상태 확인
    isLoggedIn(): boolean {
      return !!this.getToken();
    }
}
