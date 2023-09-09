import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private loggedIn = false;

  login() {
    // 로그인 처리
    this.loggedIn = true;
  }

  logout() {
    // 로그아웃 처리
    this.loggedIn = false;
  }

  isLoggedIn() {
    return this.loggedIn;
  }
}