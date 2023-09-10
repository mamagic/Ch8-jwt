import { Injectable } from '@angular/core';
import { AuthService } from './AuthService'
import {
  HttpInterceptor,
  HttpRequest,
  HttpHandler,
  HttpEvent,
} from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {
    // JWT 토큰 가져오기 (AuthService에서 정의한 메서드 활용)
    const token = this.authService.getToken();

    // 토큰이 존재하면 요청 헤더에 추가
    if (token) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`,
        },
      });
    }

    // 수정된 요청 처리
    return next.handle(req);
  }

  constructor(private authService: AuthService) {}
}
